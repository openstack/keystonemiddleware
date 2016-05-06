# Copyright 2014 Mirantis Inc
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Thread-safe connection pool for python-memcached."""

# NOTE(yorik-sar): this file is copied between keystone and keystonemiddleware
# and should be kept in sync until we can use external library for this.

import collections
import contextlib
import itertools
import logging
import time

from six.moves import queue

from keystonemiddleware.i18n import _LC


_PoolItem = collections.namedtuple('_PoolItem', ['ttl', 'connection'])


class ConnectionGetTimeoutException(Exception):
    pass


class ConnectionPool(queue.Queue):
    """Base connection pool class.

    This class implements the basic connection pool logic as an abstract base
    class.
    """

    def __init__(self, maxsize, unused_timeout, conn_get_timeout=None):
        """Initialize the connection pool.

        :param maxsize: maximum number of client connections for the pool
        :type maxsize: int
        :param unused_timeout: idle time to live for unused clients (in
                               seconds). If a client connection object has been
                               in the pool and idle for longer than the
                               unused_timeout, it will be reaped. This is to
                               ensure resources are released as utilization
                               goes down.
        :type unused_timeout: int
        :param conn_get_timeout: maximum time in seconds to wait for a
                                 connection. If set to `None` timeout is
                                 indefinite.
        :type conn_get_timeout: int
        """
        queue.Queue.__init__(self, maxsize)
        self._unused_timeout = unused_timeout
        self._connection_get_timeout = conn_get_timeout
        self._acquired = 0
        self._LOG = logging.getLogger(__name__)

    def _create_connection(self):
        raise NotImplementedError

    def _destroy_connection(self, conn):
        raise NotImplementedError

    @contextlib.contextmanager
    def acquire(self):
        try:
            conn = self.get(timeout=self._connection_get_timeout)
        except queue.Empty:
            self._LOG.critical(_LC('Unable to get a connection from pool id '
                                   '%(id)s after %(seconds)s seconds.'),
                               {'id': id(self),
                                'seconds': self._connection_get_timeout})
            raise ConnectionGetTimeoutException()
        try:
            yield conn
        finally:
            self.put(conn)

    def _qsize(self):
        return self.maxsize - self._acquired

    if not hasattr(queue.Queue, '_qsize'):
        qsize = _qsize

    def _get(self):
        if self.queue:
            conn = self.queue.pop().connection
        else:
            conn = self._create_connection()
        self._acquired += 1
        return conn

    def _put(self, conn):
        self.queue.append(_PoolItem(
            ttl=time.time() + self._unused_timeout,
            connection=conn,
        ))
        self._acquired -= 1
        # Drop all expired connections from the right end of the queue
        now = time.time()
        while self.queue and self.queue[0].ttl < now:
            conn = self.queue.popleft().connection
            self._destroy_connection(conn)


class MemcacheClientPool(ConnectionPool):
    def __init__(self, urls, dead_retry=None, socket_timeout=None, **kwargs):
        ConnectionPool.__init__(self, **kwargs)
        self._urls = urls
        self._dead_retry = dead_retry
        self._socket_timeout = socket_timeout

        # NOTE(morganfainberg): The host objects expect an int for the
        # deaduntil value. Initialize this at 0 for each host with 0 indicating
        # the host is not dead.
        self._hosts_deaduntil = [0] * len(urls)

        # NOTE(morganfainberg): Lazy import to allow middleware to work with
        # python 3k even if memcache will not due to python 3k
        # incompatibilities within the python-memcache library.
        global memcache
        import memcache

        # This 'class' is taken from http://stackoverflow.com/a/22520633/238308
        # Don't inherit client from threading.local so that we can reuse
        # clients in different threads
        MemcacheClient = type('_MemcacheClient', (object,),
                              dict(memcache.Client.__dict__))

        self._memcache_client_class = MemcacheClient

    def _create_connection(self):
        return self._memcache_client_class(self._urls,
                                           dead_retry=self._dead_retry,
                                           socket_timeout=self._socket_timeout)

    def _destroy_connection(self, conn):
        conn.disconnect_all()

    def _get(self):
        conn = ConnectionPool._get(self)
        try:
            # Propagate host state known to us to this client's list
            now = time.time()
            for deaduntil, host in zip(self._hosts_deaduntil, conn.servers):
                if deaduntil > now and host.deaduntil <= now:
                    host.mark_dead('propagating death mark from the pool')
                host.deaduntil = deaduntil
        except Exception:
            # We need to be sure that connection doesn't leak from the pool.
            # This code runs before we enter context manager's try-finally
            # block, so we need to explicitly release it here
            ConnectionPool._put(self, conn)
            raise
        return conn

    def _put(self, conn):
        try:
            # If this client found that one of the hosts is dead, mark it as
            # such in our internal list
            now = time.time()
            for i, deaduntil, host in zip(itertools.count(),
                                          self._hosts_deaduntil,
                                          conn.servers):
                # Do nothing if we already know this host is dead
                if deaduntil <= now:
                    if host.deaduntil > now:
                        self._hosts_deaduntil[i] = host.deaduntil
                    else:
                        self._hosts_deaduntil[i] = 0
            # If all hosts are dead we should forget that they're dead. This
            # way we won't get completely shut off until dead_retry seconds
            # pass, but will be checking servers as frequent as we can (over
            # way smaller socket_timeout)
            if all(deaduntil > now for deaduntil in self._hosts_deaduntil):
                self._hosts_deaduntil[:] = [0] * len(self._hosts_deaduntil)
        finally:
            ConnectionPool._put(self, conn)

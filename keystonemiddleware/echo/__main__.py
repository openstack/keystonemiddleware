from keystonemiddleware.echo import service


try:
    service.EchoService()
except KeyboardInterrupt:
    pass

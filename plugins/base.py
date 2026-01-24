class OWASPPlugin:
    id = "A00"
    name = "Base Plugin"

    def scan(self, url, response, soup):
        raise NotImplementedError("Plugins must implement scan()")

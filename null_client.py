"""
Send and Recieve messages to the NULL IFF Location server
"""
import identity
import null_proto
import urllib

class Client(object):
    def __init__(self, signer, server, serverpub):
        self.singer = signer
        self.ecdhkey = None
        self.sessionkey = None
        self.server = server.rstrip("/")
        self.serverpub = serverpub

    def post(self, path, message):
        """
        Send a urlencoded POST message and get the response
        :param path: url path
        :param message: string to send
        :return:
        """
        params = urllib.urlencode(str(message))
        conn = urllib.urlopen(self.server + "/" + path, params)
        data = conn.read()
        return data

    def connect(self):
        """
        Handshake with the server
        :return:
        """
        self.ecdhkey = identity.genkey()
        send = null_proto.client_handshake_begin(self.singer, self.ecdhkey, self.serverpub)



"""
Send and Recieve messages to the NULL IFF Location server
"""
import identity
import null_proto
import urllib
import json


class Client(object):
    def __init__(self, signer, server, serverpub):
        self.signer = signer
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
        conn = urllib.urlopen(self.server + path, message)
        data = conn.read()
        return data

    def connect(self):
        """
        Handshake with the server
        :return:
        """
        self.ecdhkey = identity.genkey()
        self.sessionkey, send = null_proto.client_handshake_begin(self.signer, self.ecdhkey, self.serverpub)
        response = self.post("/handshake_begin", json.dumps(send))
        response = json.loads(response)

        send = null_proto.client_handshake_finish(self.signer, self.sessionkey, response)

        response = self.post("/handshake_finish", json.dumps(send))
        response = json.loads(response)

        assert "status" in response, "expected status in response"
        assert response["status"] == "complete", "expected status == complete"

    def submit_location(self, cmdr, system, group):
        """
        Send our location
        :param cmdr:
        :param system:
        :param group:
        :return:
        """

        data = {
            "cmdr": cmdr,
            "system": system,
            "group": group,
        }

        send = null_proto.send_data(self.signer, self.sessionkey, json.dumps(data))

        response = self.post("/submit_location", json.dumps(send))

        return json.loads(response)

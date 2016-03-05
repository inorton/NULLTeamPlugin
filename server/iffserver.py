#!/usr/bin/python
"""
The IFF Server!

The protocol:

Getting SSL into the binary distribution of EDMC is non-trivial so we have a simple authentication scheme based
on ECDSA and ECDHE

"""
import threading
import time
import os
import libs
import json

import identity
import web
import uuid

MAX_LOCATION_AGE = 600

challenges = dict()
chlock = threading.Semaphore()
cmdrs = dict()
cmdrslock = threading.Semaphore()

# server's identity is this folder, if we don't have one, generate
KEYFILE = identity.get_priv_keyfilename(libs.THISDIR)
if not os.path.exists(KEYFILE):
    identity.first_run(libs.THISDIR)
PRIVKEY = identity.load(identity.get_priv_keyfilename(libs.THISDIR))


def run():
    urls = ("/Challenge", "Challenge",
            "/ReportLocation", "ReportLocation",)
    app = web.application(urls, globals())
    app.run()


def encode_message(challenge, payload):
    """
    Encode the message into something we can sign/verify
    :param challenge:
    :param payload:
    :return:
    """
    message = {
        "challenge": challenge,
        "message": payload
    }
    return json.dumps(message)


def sign_mesage(privkey, challenge, payload):
    """
    Encode/Sign the message
    :param privkey:
    :param challenge:
    :param payload:
    :return:
    """
    message = encode_message(challenge, payload)
    signature = identity.sign_string(privkey, message)

    return json.dumps({
        "signature": signature,
        "challenge": challenge,
        "message": payload
    })


def verify_message(message):
    """
    Decode and verify the message
    :param message:
    :return:
    """
    payload = encode_message(message["challenge"], message["message"])
    signature = message["signature"]
    pubkeystr = message["message"]["pubkey"]
    pubkey = identity.loadpubstr(pubkeystr)
    return identity.verify_string(pubkey, signature, payload)

class Commander(object):
    """
    Represent a commander + location + identity
    """
    def __init__(self, name=None, location=None, timestamp=0):
        self.trustlevel = 0
        self.name = name
        self.location = location
        self.timestamp = timestamp
        self.pubkey = None
        self.datakey = None

    def load(self, dictionary):
        """
        Load a commander from this dictionary
        :param dictionary:
        :return:
        """
        self.name = dictionary["name"]
        self.location = dictionary["location"]
        self.timestamp = time.time()

    def compute_session_key(self, user_signed_hello):
        """
        Compute a session key with the user's ephemeral EC key
        :param user_signed_hello:
        :return:
        """
        pass


    def expired(self):
        """
        Return true if this is expured
        :return:
        """
        now = time.time()
        return now - self.timestamp > MAX_LOCATION_AGE


class Hello:
    """
    Client sends us it's signed ephemeral public key, We verify.
    Client should already have our public key.
    Save the session key if the Hello verifies.

    Sig(client, client_tmp_pub), client_pub, client_tmp_pub

    """
    def POST(self):
        postdata = web.data()
        request = json.loads(postdata)
        # {
        #   tmp_pub: ephemeral_pubkey,
        #   pub: client_pubkey,
        #   tmp_pub_signed: ephemeral_pubkey_signed_by_client_priv
        # }



        return ""


class ReportLocation:
    def POST(self):
        postdata = web.data()
        request = json.loads(postdata)
        with chlock:
            prune_challenges()
            challenge = request["challenge"]
            if challenge not in challenges:
                raise web.notfound()
            if not verify_message(request):
                raise web.unauthorized()

        # we have a valid message, insert it into our records
        with cmdrslock:
            cmdr = request["message"]["name"]



if __name__ == "__main__":
    run()
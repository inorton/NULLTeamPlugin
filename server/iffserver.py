#!/usr/bin/python
"""
The IFF Server!

The protocol:

Getting SSL into the binary distribution of EDMC is non-trivial so we have a simple authentication scheme based
on ECDSA and ECDHE

"""
import threading
import hashlib
import time
import os
import libs
import json

import identity
import web
import null_proto

MAX_LOCATION_AGE = 600


# things connecting to us
pending_sessions = dict()
# sessions that have completed handshakes
sessions = dict()
session_lock = threading.Semaphore()

cmdrs = dict()
cmdrs_lock = threading.Semaphore()

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


def encode_message(payload):
    """
    Encode the message into something we can send/encrypt or sign
    :param challenge:
    :param payload:
    :return:
    """
    message = {
        "message": payload
    }
    return json.dumps(message)


class Session(object):
    """
    A connection to a client
    """
    def __init__(self):
        self.trusted = False
        self.secret = None
        self.pubkey = None
        self.commander = None
        self.challenge_plain = None
        self.started = time.time()


class Commander(object):
    """
    Represent a commander + location + identity
    """
    def __init__(self, name=None, location=None, timestamp=0):
        self.trustlevel = 0
        self.name = name
        self.location = location
        self.timestamp = timestamp
        self.verified = False
        self.pubkey = None   # long term pubkey
        self.datakey = None  # secret key for this session

    def load(self, dictionary):
        """
        Load a commander from this dictionary
        :param dictionary:
        :return:
        """
        self.name = dictionary["name"]
        self.location = dictionary["location"]
        self.timestamp = time.time()

    def expired(self):
        """
        Return true if this is expured
        :return:
        """
        now = time.time()
        return now - self.timestamp > MAX_LOCATION_AGE


class handshake_begin:
    """
    null protocol handshake begin
    """
    def POST(self):
        postdata = web.data()
        request = json.loads(postdata)

        server_secret, gotpub, challenge, challenge_plain = null_proto.server_handshake_begin(PRIVKEY, request)

        session = Session()
        session.secret = server_secret
        session.pubkey = gotpub
        session.challenge_plain = challenge_plain
        pubhash = hashlib.sha512(gotpub.from_der()).hexdigest()

        with session_lock:
            pending_sessions[pubhash] = session

        return json.dumps(challenge)


class handshake_finish:
    """
    null protocol handshake completion
    """
    def POST(self):
        postdata = web.data()
        request = json.loads(postdata)

        pubhash = request["fingerprint"]
        with session_lock:
            assert pubhash in pending_sessions
            session = pending_sessions[pubhash]
            result = null_proto.server_handshake_finish(session.pubkey, session.challenge_plain, request)

            # session ready

            return json.dumps(result)


if __name__ == "__main__":
    run()

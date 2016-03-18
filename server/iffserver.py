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
MAX_SESSION_AGE = 600
MAX_PENDING_SESSION_AGE = 60

# things connecting to us
pending_sessions = dict()
# sessions that have completed handshakes
sessions = dict()
session_lock = threading.Semaphore()


# server's identity is this folder, if we don't have one, generate
KEYFILE = identity.get_priv_keyfilename(libs.THISDIR)
if not os.path.exists(KEYFILE):
    identity.first_run(libs.THISDIR)
PRIVKEY = identity.load(identity.get_priv_keyfilename(libs.THISDIR))


def run():
    urls = ("/handshake_begin", "handshake_begin",
            "/handshake_finish", "handshake_finish",
            "/submit_location", "submit_location",)
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
        self.handshake_done = False

    def age(self):
        """
        how old this session in seconds
        :return:
        """
        return time.time() - self.started


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
        self.session = None
        self.pubkey = None
        self.signatures = []
        self.revoked = False

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


def clean_sessions():
    """
    clean up pending/old sessions
    :return:
    """
    with session_lock:
        remove = []
        for pubhash in pending_sessions:
            if pending_sessions[pubhash].age() > MAX_PENDING_SESSION_AGE:
                remove.append(pubhash)
        for pubhash in remove:
            del(pending_sessions[pubhash])
        remove = []
        for pubhash in sessions:
            if sessions[pubhash].age() > MAX_SESSION_AGE:
                remove.append(pubhash)
        for pubhash in remove:
            del(pending_sessions[pubhash])


class handshake_begin:
    """
    null protocol handshake begin
    """
    def POST(self):
        clean_sessions()

        postdata = web.data()
        request = json.loads(postdata)

        server_secret, gotpub, challenge, challenge_plain = null_proto.server_handshake_begin(PRIVKEY, request)

        session = Session()
        session.secret = server_secret
        session.pubkey = gotpub
        session.challenge_plain = challenge_plain
        pubhash = identity.pubkeyhash(gotpub)

        with session_lock:
            pending_sessions[pubhash] = session

        return json.dumps(challenge)

    def GET(self):
        return "the server is running"


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
            session.commander = Commander()
            session.commander.session = session
            session.commander.pubkey = session.pubkey
            session.handshake_done = True

            del(pending_sessions[pubhash])
            sessions[pubhash] = session

            return json.dumps(result)


class submit_location:
    """
    Accept a new signed location from a client that has already completed handshake
    """
    def POST(self):
        postdata = web.data()
        request = json.loads(postdata)

        pubhash = request["fingerprint"]
        assert pubhash in sessions
        session = sessions[pubhash]
        message = null_proto.receive_data(session.pubkey,
                                          session.secret,
                                          request)
        location = json.loads(message)

        assert "cmdr" in location
        assert "system" in location
        assert "group" in location

        return json.dumps({"status":"complete"})


if __name__ == "__main__":
    run()

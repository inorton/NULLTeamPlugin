#!/usr/bin/python
"""
The IFF Server!

The protocol:

Getting SSL into the binary distribution of EDMC is non-trivial so we have a simple authentication scheme based on ECDSA
challenges and responses in each message. Challenges are like treated like single use tokens/cookies

Client Connects,
Client Requests a Challenge
-> Server Generates a random challenge message
   Server keeps a record of the last 2 minutes of challenges.
   Server signs challenge and returns it and the signature to the client.
<- Signature, Challenge = Sig(Challenge)

Client verifies Challenge signature
+++ Client now trusts server +++

Client Creates message (ie, some kind of request or posted data), challenge is embedded in the message
 Client signs (message)
 Client sends message, signature to server

Server Verifies signature, Checks challenge is in the active challenges.
+++ Server now trusts Client signed the challenge we gave out +++

If the message is a "I am here" store the data, Expire after 30 minutes.

If the message is a "Who is here" then send them Signed results based on who has trusted their public key.

This whole thing obviously doesn't guard against someone sniffing the network traffic. But this is hardly top-secret
data, it is just a game!

Message Types:

void ReportLocation(signature, challenge, cmdr_name, location, pvtgroup)

list(cmdrs) PollLocations(signature, challenge, location)
 each cmdr in the list is basically a dictionary, {
   CmdrName: Name,
   TrustLevel: (number of top level signatures),
   Location: (location text,  exactly the same form as in ReportLocation)
 }

"""
import threading
import time
import os
import libs
import json

import identity
import web
import uuid

MAX_CHALLENGE_AGE = 120

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


def prune_challenges():
    """
    Clean out old challenges
    :return:
    """
    now = time.time()
    delete = list()
    for ch in list(challenges):
        timestamp = challenges[ch]
        if now - timestamp > MAX_CHALLENGE_AGE:
            delete.append(ch)
    for ch in delete:
        del(challenges[ch])


def make_challenge():
    """
    Create a challenge, basically just a uuid and store it
    :return:
    """
    challenge = str(uuid.uuid4())
    assert challenge not in challenges  # this should never happen, its a uuid!

    challenges[challenge] = time.time()
    return challenge


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


class Challenge:
    def GET(self):
        with chlock:
            prune_challenges()
            challenge = make_challenge()
            return sign_mesage(PRIVKEY, challenge, "")


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
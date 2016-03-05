"""
Test suite for null_proto
"""

import binascii
import pytest
import os
import identity
import null_proto

@pytest.fixture()
def temp_client():
    """
    :return:
    """
    longterm = identity.genkey()
    longterm_pub = longterm.get_verifying_key()

    session = identity.genkey()
    session_pub = session.get_verifying_key()

    return {"longterm": longterm,
            "longterm_pub": longterm_pub,
            "session": session,
            "session_pub": session_pub}


def test_handshake(temp_client):
    """
    Test the handshake
    :return:
    """
    serverpriv = identity.genkey()
    serverpub = serverpriv.get_verifying_key()

    secret, message = null_proto.client_handshake_begin(temp_client["longterm"],
                                                        temp_client["session"],
                                                        serverpub)

    assert secret
    assert message

    server_secret, gotpub, challenge, challenge_plain = null_proto.server_handshake_begin(serverpriv, message)

    assert secret == server_secret

    response = null_proto.client_handshake_finish(temp_client["longterm"],
                                                  server_secret, challenge)

    complete = null_proto.server_handshake_finish(gotpub,
                                                  challenge_plain, response)

    assert "status" in complete
    assert complete["status"] == "complete"


def test_encrypt():
    """
    Test encrypt/decrypt
    :return:
    """
    secret = os.urandom(16)
    for size in range(64, 1024, 157):
        message = binascii.hexlify(os.urandom(size))

        ctext, iv = null_proto.aes_encrypt_str(secret, message)

        ptext = null_proto.aes_decrypt_str(secret, iv, ctext)

        assert message == ptext

"""
Test suite for null_proto
"""

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

    server_secret, gotpub, challenge = null_proto.server_handshake_begin(serverpriv, message)

    assert secret == server_secret



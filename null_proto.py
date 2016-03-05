"""
The NULL Crypto Protocol

This is a simple (and probably not very robust) ECDHE + AES protocol using ECDSA for authentication. Please don't use
this for anything important!!

The server has a list of trusted public keys, the client the public key of the server it trusts.

When connecting a new session, the client uses an ephemeral ECDH key signed by the client's long-term ECDSA key.
The server enforces that only one ephemeral ECDH key can be in use for each client key.

Handshake:
* Client sends it's pubkey and epehemeral pubkey, and sign the ephemeral pubkey and sends that.
* The client computes a shared secret to use as an AES128 key between the ephemeral ECDH key and the
  server's public key.
* If the server trusts the client's ECDSA key it computes the same shared secret using ECDH
* The server encrypts a random string using the shared key and sends it to the client.
* The client must decrypt and sign the plain text version of the string.
* The server verifies this final exchange and trusts the client.

"""

import identity
import hashlib
import pyaes
import uuid

KDFS = [
    "NULLAES128sha256str"
]
DEFAULT_KDF = "NULLAES128sha256str"


def aes_encrypt_str(key, plaintext):
    """
    Encrypt a string with AES.
    :param key:
    :param plaintext:
    :return:
    """
    iv = str(uuid.uuid4())[-16:]
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv))
    return encrypter.feed(plaintext)


def aes_decrypt_str(key, ciphertext):
    """
    Decrypt a string with AES
    :param key:
    :param ciphertext:
    :return:
    """
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key))
    return decrypter.feed(ciphertext)


def derive_key(kdf, shared):
    """
    Derive our secret key
    :param kdf:
    :param shared: shared secret ecpoints
    :return:
    """
    assert kdf in KDFS
    if kdf == "NULLAES128sha256str":
        # 128bit AES key from the last part of the sha256 hash if the ecpoint string representation
        keydata = hashlib.sha256(str(shared)).digest()[-16:]
        return keydata
    else:
        raise KeyError("no such KDF " + kdf)


def server_handshake_begin(server_priv, message):
    """
    Receive the handshake
    :param server_priv: server private key
    :param message: message data (decoded)
    :return: secret aes key, client's pubkey, handshake response to send
    """
    assert server_priv.curve.openssl_name == message["keytype"]
    signature = message["signature"]

    client_pub = identity.loadpubstr(message["pub"])  # client long term key
    session_pub = identity.loadpubstr(message["session"])  # client session ecc key

    verify_msg = message["session"] + message["kdf"] + message["keytype"]

    assert identity.verify_string(client_pub, signature, verify_msg) is True

    shared = identity.ecdh(server_priv, session_pub)
    secret = derive_key(message["kdf"], shared)

    challenge = aes_encrypt_str(secret, str(uuid.uuid4()))
    response = {"challenge": challenge}
    return secret, client_pub, response


def client_handshake_begin(ecdsa_priv, ecdh_priv, server_pub, curve=identity.DEFAULT_KEYTYPE, kdf=DEFAULT_KDF):
    """
    Start the handshake
    :param ecdsa_priv: long term signing privkey
    :param ecdh_priv: temporary session ecc privkey
    :param server_pub: server long term pub key
    :param curve: EC Curve name
    :param kdf: Key derivation mechanism
    :return: secret aes key, handshake message to send
    """

    session_pub_str = ecdh_priv.get_verifying_key().to_pem()

    # sign our session key
    signature = identity.sign_string(ecdsa_priv, session_pub_str + kdf + curve.openssl_name)

    message = {
        "pub": ecdsa_priv.get_verifying_key().to_pem(),
        "session": session_pub_str,
        "signature": signature,
        "keytype": curve.openssl_name,
        "kdf": kdf,
    }

    shared = identity.ecdh(ecdh_priv, server_pub)
    secret = derive_key(kdf, shared)

    return secret, message


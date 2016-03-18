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

import os
import binascii
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
    iv = os.urandom(16)
    encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(key, iv))
    ctext = encrypter.feed(plaintext)
    ctext += encrypter.feed()
    return binascii.hexlify(ctext), binascii.hexlify(iv)


def aes_decrypt_str(key, iv, ciphertext):
    """
    Decrypt a string with AES
    :param key:
    :param iv:
    :param ciphertext:
    :return:
    """
    iv = binascii.unhexlify(iv)
    ciphertext = binascii.unhexlify(ciphertext)
    decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(key, iv))
    ptext = decrypter.feed(ciphertext)
    ptext += decrypter.feed()
    return ptext


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

    challenge_plain = str(uuid.uuid4())

    challenge, iv = aes_encrypt_str(secret, challenge_plain)
    response = {"challenge": challenge, "iv": iv}
    return secret, client_pub, response, challenge_plain


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


def client_handshake_finish(client_priv, secret, challenge):
    """
    Sign the challenge from the server's handshake response
    :param client_priv:
    :param secret:
    :param challenge:
    :return:
    """
    pubkeyhash = identity.pubkeyhash(client_priv.get_verifying_key())
    plaintext = aes_decrypt_str(secret, challenge["iv"], challenge["challenge"])
    signature = identity.sign_string(client_priv, plaintext)
    return {"signature": signature,
            "fingerprint": pubkeyhash
            }


def server_handshake_finish(client_pub, challenge, response):
    """
    Verify the client processed our handshake correctly
    :param client_pub: client's long term public key
    :param challenge: challenge plaintext
    :param response: message containing a signature of the plaintext and hash of the singer pubkey
    :return:
    """
    assert "fingerprint" in response
    pubkeyhash = hashlib.sha512(client_pub.to_der()).hexdigest()
    assert pubkeyhash == response["fingerprint"]
    assert identity.verify_string(client_pub, response["signature"], challenge)
    return {"status": "complete"}


def send_data(signer, sessionkey, data):
    """
    Encrypt some data and sign it
    :param signer: signing key
    :param sessionkey: encryption key
    :param data: message (expected string)
    :return: dict containing fingerprint, signature, iv and ciphertext
    """
    ctext, iv = aes_encrypt_str(sessionkey, str(data))
    signature = identity.sign_string(signer, ctext)
    pubkeyhash = hashlib.sha512(signer.get_verifying_key().to_der()).hexdigest()

    return {
        "fingerprint": pubkeyhash,
        "signature": signature,
        "iv": iv,
        "ciphertext": ctext
    }


def receive_data(pubkey, sessionkey, data):
    """
    Verify and Decrypt a message
    :param pubkey: the sender's signing key
    :param sessionkey: the encryption key
    :param data: (string)
    :return: the plain text if the message verifies
    """
    pubkeyhash = hashlib.sha512(pubkey.to_der()).hexdigest()
    assert pubkeyhash == data["fingerprint"]
    assert identity.verify_string(pubkey,
                                  data["signature"],
                                  data["ciphertext"])

    return aes_decrypt_str(sessionkey,
                           data["iv"],
                           data["ciphertext"])

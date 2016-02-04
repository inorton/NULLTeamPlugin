import binascii
import hashlib
import os

from ecdsa import SigningKey, curves
from ecdsa import util as ecdsautil


def genkey():
    """
    Generate an ECDSA key
    :return:
    """
    return SigningKey.generate(curve=curves.NIST192p)


def savekey(keypair, path, name):
    """
    Save a keypair as PEM files
    :param keypair:
    :param path:
    :param name:
    :return:
    """
    privname = os.path.join(path, name + ".priv")
    pubname = os.path.join(path, name + ".pub")

    with open(privname, "wb") as privfile:
        privfile.write(keypair.to_pem())
    with open(pubname, "wb") as pubfile:
        pubfile.write(keypair.get_verifying_key().to_pem())


def load(privkeypem):
    """
    Load a private key from disk
    :param privkeypem:
    :return:
    """
    with open(privkeypem, "rb") as privfile:
        return SigningKey.from_pem(privfile.read())


def sign_string(privkey, message):
    """
    Sign a string
    :param privkey:
    :param message:
    :return:
    """
    data = str(message)
    sig = privkey.sign(data, hashfunc=hashlib.sha1, sigencode=ecdsautil.sigencode_der)
    return binascii.hexlify(sig)


def verify_string(pubkey, signature, message):
    """
    Verify
    :param pubkey:
    :param signature:
    :param message:
    :return:
    """
    data = str(message)
    signature = binascii.unhexlify(signature)
    return pubkey.verify(signature, data, hashfunc=hashlib.sha1, sigdecode=ecdsautil.sigdecode_der)


def test_genkey():
    """
    Test key generation
    :return:
    """
    key = genkey()
    assert key

    savekey(key, ".", "test")

    loaded = load("test.priv")

    signed = sign_string(loaded, "hello")

    pubkey = loaded.get_verifying_key()

    assert(verify_string(pubkey, signed, "hello"))


if __name__ == "__main__":
    test_genkey()


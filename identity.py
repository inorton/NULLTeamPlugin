import binascii
import hashlib
import os
import sys

from ecdsa import SigningKey, VerifyingKey, curves
from ecdsa import ecdsa
from ecdsa import util as ecdsautil

def get_keys_folder(datafolder):
    """
    :param datafolder:
    :return:
    """
    return os.path.join(datafolder, "keys")

def get_pub_keyfilename(datafolder):
    """
    :param datafolder:
    :return:
    """
    keyfolder = get_keys_folder(datafolder)
    return os.path.join(keyfolder, "identity.pub")


def get_priv_keyfilename(datafolder):
    """
    :param datafolder:
    :return:
    """
    keyfolder = get_keys_folder(datafolder)
    return os.path.join(keyfolder, "identity.priv")


def first_run(datafolder):
    """
    Do our first run and generate keys
    :param datafolder:
    :return:
    """
    keyfolder = get_keys_folder(datafolder)
    if not os.path.exists(keyfolder):
        os.makedirs(keyfolder)
    if not os.path.isfile(get_priv_keyfilename(datafolder)):
        key = genkey()
        savekey(key, keyfolder, "identity")
        sys.stderr.write("ident key generated\n")


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


def loadpub(pubkeypem):
    """
    Load a public key from a PEM file
    :param pubkeypem:
    :return:
    """
    with open(pubkeypem, "rb") as pubfile:
        return loadpubstr(pubfile.read())


def loadpubstr(pemstring):
    """
    Load a public key from PEM string
    :param pemstring:
    :return:
    """
    return VerifyingKey.from_pem(pemstring)


def get_pubkey(datafolder):
    """
    Return the public key pem file
    :param datafolder:
    :return:
    """
    filename = get_pub_keyfilename(datafolder)
    if os.path.exists(filename):
        with open(filename, "r") as filehandle:
            return filehandle.read()
    return None


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


def ecdh(privkey, pubkey):
    """
    Given a loaded private key and a loaded public key, perform an ECDH exchange
    :param privkey:
    :param pubkey:
    :return:
    """
    return ecdsa.ecdh(privkey, pubkey)

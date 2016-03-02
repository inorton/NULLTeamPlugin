"""
Py.Test tests for identity.py
"""
import os
import identity


def test_generate_sign(tmpdir):
    """
    Test key generation
    :param tmpdir:
    :return:
    """
    datafolder = tmpdir.strpath
    identity.first_run(datafolder)
    keyfile = identity.get_priv_keyfilename(datafolder)

    assert os.path.isfile(keyfile)

    key = identity.load(keyfile)
    signature = identity.sign_string(key, "hello")

    pub = identity.loadpub(identity.get_pub_keyfilename(datafolder))
    assert identity.verify_string(pub, signature, "hello")


def test_ecdh(tmpdir):
    """
    Test and ECDH key exchange
    :param tmpdir:
    :return:
    """
    alicedir = os.path.join(tmpdir.strpath, "alice")
    os.makedirs(alicedir)

    identity.first_run(alicedir)
    alicepriv = identity.get_priv_keyfilename(alicedir)
    aliceprivkey = identity.load(alicepriv)

    bobdir = os.path.join(tmpdir.strpath, "bob")
    os.makedirs(bobdir)

    identity.first_run(bobdir)
    bobpriv = identity.get_priv_keyfilename(bobdir)
    bobprivkey = identity.load(bobpriv)

    alicepub = identity.loadpub(identity.get_pub_keyfilename(alicedir))
    bobpub = identity.loadpub(identity.get_pub_keyfilename(bobdir))

    shared_bob = identity.ecdh(bobprivkey, alicepub)
    shared_alice = identity.ecdh(aliceprivkey, bobpub)

    assert shared_alice == shared_bob
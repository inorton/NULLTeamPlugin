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

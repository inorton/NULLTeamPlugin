"""
Test the NULL protocol HTTP client
"""
import subprocess
import null_client
import pytest
import time
import identity
import os
import socket


THISDIR = os.path.dirname(__file__)
SERVER = os.path.join(THISDIR, "server")
MYIP = socket.gethostbyname(socket.gethostname())

@pytest.fixture()
def run_server(request):
    """
    Run the server as a background process
    :return:
    """
    cmd = ["python", "iffserver.py"]

    proc = subprocess.Popen(cmd, cwd=SERVER)

    def fin():
        """
        Kill off the server
        :return:
        """
        proc.terminate()
    if request:
        request.addfinalizer(fin)

    pubkey = identity.get_pub_keyfilename(os.path.join(SERVER, "libs"))
    waited = 0
    while not os.path.exists(pubkey):
        time.sleep(2)
        waited += 2
        assert proc.returncode is None
        assert waited < 60, "server did not generate a keypair!"

    serverpub = identity.loadpub(pubkey)

    return proc, serverpub


def test_client_handshake(run_server):
    """
    Connect to the server and do a handshake
    :param run_server:
    :return:
    """
    proc, serverpub = run_server
    assert proc
    assert serverpub
    privkey = identity.genkey()
    client = null_client.Client(privkey, "http://{}:8080".format(MYIP), serverpub)

    client.connect()

    client.submit_location("Ian Norton", "Lave", "Open")


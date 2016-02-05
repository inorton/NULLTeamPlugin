"""
The NULL Team/Faction Cooperation Plugin
"""
import sys
import os
import ttk
import Tkinter as tk
import json

THISFILE = os.path.abspath(__file__)
THISDIR = os.path.dirname(THISFILE)

sys.path.insert(0, THISDIR)

import identity
import myNotebook as nb

PLUGNAME = "NULLTeam"


def plugin_start():
    """
    Start this plugin
    :return:
    """
    sys.stderr.write(PLUGNAME + " plugin started\n")  # appears in %TMP%/EDMarketConnector.log in packaged Windows app
    identity.first_run(THISDIR)


def plugin_prefs(parent):
    """
    Return a TK Frame for adding to the EDMC settings dialog.
    """
    frame = nb.Frame(parent)

    return frame


def system_changed(timestamp, system):
    """
    Arrived in a new System
    :param timestamp: when we arrived
    :param system: the name of the system
    :return:
    """
    sys.stderr.write("Arrived at {}\n".format(system))


def cmdr_data(data):
    """
    Obtained new data from Frontier about our commander, location and ships
    :param data:
    :return:
    """
    cmdr_data.last = data
    with open(os.path.join(os.getenv("TMP"), "cmdr.json"), "wb") as fh:
        print >> fh, json.dumps(data,
                                sort_keys=True,
                                indent=4,
                                separators=(',', ': '))
cmdr_data.last = None

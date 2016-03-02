"""
Control paths used for imports
"""
import sys
import os


def dirname(pathstr):
    return os.path.dirname(pathstr)


THISDIR = dirname(os.path.abspath(__file__))
OUTER = dirname(dirname(THISDIR))
if OUTER not in sys.path:
    sys.path.append(OUTER)

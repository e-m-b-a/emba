#!/usr/bin/python3
"""
EMBA - EMBEDDED LINUX ANALYZER

Copyright 2025-2025 Thomas Gingele <b1tc0r3@proton.me>

EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

EMBA is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only

Author(s): Thomas Gingele

Description: This file converts EMBAs formatting variables into values
             which can be used by Python.
"""
import re

from os import environ


FORMAT = {}


def generate_format():
    """
    This function grabs all available formatting codes
    from the environment variables via a regex
    and populates the FORMAT dictionary with them
    """
    global FORMAT

    pattern = r"^\\033\[[;0-9]+m$"
    for key in environ:
        if re.search(pattern, environ[key]):
            FORMAT[key] = environ[key].replace("\\033", "\x1b")


if __name__ != "__main__" and len(FORMAT) == 0:
    generate_format()

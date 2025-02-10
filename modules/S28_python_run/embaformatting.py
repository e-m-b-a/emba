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
# pylint: disable=R0903  # Disable 'to few public methods' warning for Format
#                        # class because it is equivalent to an Enum
import re

from os import environ


class FormatMeta(type):
    """
    Metaclass for a Singlton of type Format.
    """

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance

        return cls._instances[cls]


class Format(metaclass=FormatMeta):
    """
    Class holding all formatting/color codes from the EMBA environment
    variables as attributes.
    """

    def __init__(self):
        """
        This function grabs all available formatting codes
        from the environment variables via a regex
        and adds them to the Format instance as attributes.
        """
        pattern = r"^\\033\[[;0-9]+m$"
        for key in environ:
            if re.search(pattern, environ[key]):
                setattr(self, key, environ[key].replace("\\033", "\x1b"))

#!/usr/bin/python3
"""
EMBA - EMBEDDED LINUX ANALYZER

Copyright 2024-2024 Thomas Gingele <b1tc0r3@proton.me>

EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

EMBA is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only

Author(s): Thomas Gingele

Description: This python script serves as an example of a Python module. It echoes passed parameters and then exits.
"""
from embamodule import setup_module, shutdown_module
from sys import argv
from os import environ


def main():
    # Setup module and logging.
    # This line is required.
    module = setup_module(argv, environ)

    # This is just some example code.
    # The module logic would go here.
    module.log("Received arguments a total of {len(environ)} environment variables.")
    for key in environ.keys():
        module.add_finding(f"Found envvar: {key}={environ[key]}")

    # Shutdown module and report results.
    # This line is required
    shutdown_module(module)

main()

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

Description: This python script serves as an example of a Python module.
             It echoes passed parameters and then exits.
"""
# pylint: disable=W0718  # The generic Exception caught in 'main' is required
#                        # to handle _all_ errors thrown by 'module_run'
from sys import argv
from os import environ
from traceback import format_exc
from embamodule import setup_module, shutdown_module
from embaformatting import Format


def module_run(module, env, fmt):
    """
    This function holds the modules logic.
    All custom code should go here or in a function called by this one.
    """
    # Create a basic log entry.
    # Colored output is supported.
    module.log(f"Envvar count: {fmt.ORANGE}{len(env)}{fmt.NC}")

    # Add a finding.
    module.add_finding("You look great today!")

    # Raise an exception.
    # All exceptions, wether intentionally raised or not are automatically
    # formatted and written to the module log.
    raise ValueError("Dummy Exception")


def main():
    """
    This function should not be changed.
    It handles the setup and reporting of the module.
    """
    module = setup_module(argv, environ)
    fmt = Format()

    try:
        module_run(module, environ, fmt)

    except Exception:
        module.panic(format_exc())

    finally:
        shutdown_module(module)


main()

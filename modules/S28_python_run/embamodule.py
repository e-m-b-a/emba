#!/usr/bin/python3
# pylint: disable=no-member
#   no-member: Attributes of the Format class are dynamically generated during
#              runtime.
"""
EMBA - EMBEDDED LINUX ANALYZER

Copyright 2024-2024 Thomas Gingele <b1tc0r3@proton.me>

EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

EMBA is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only

Author(s): Thomas Gingele

Description: This file contains wrapper code for custom Python modules.
"""
from os import _Environ
from embaformatting import Format


class EmbaModule():
    """
    Module handling class for EMBA python scripts.

    Functions:
        __init__:
            Create a new instance of the class and set up logging.

        __del__:
            Close module files and destroy the class instance.

        __write_formatted_log:
            Base method for logging. Should not be
            called by Python modules directly.

        log:
            Log a new message into the module log files.

        add_finding:
            Add a new finding to the module. This will later be
            used during report generation.

        panic:
            Ensures propper logging when throwing exceptions.
    """

    def __init__(self, argv: list, env: _Environ):
        self.format = Format()
        self.findings = []
        self.filename = argv[0].split("/")[-1].split('.')[0]

        try:
            self.logfile_dir = env.get('LOG_PATH_MODULE')
            self.logfile = f"{self.logfile_dir}/{self.filename}.txt"

        except KeyError as key_error:
            err = f"Unable to determine log path for module '{self.filename}'."
            self.panic(err)
            raise key_error

        except PermissionError as perm_error:
            err = f"Access to '{self.filename}.py' denied."
            self.panic(err)
            raise perm_error

        except FileNotFoundError as file_not_found_error:
            err = f"Unable to access '{self.filename}'."
            self.panic(err)
            raise file_not_found_error

    def __write_formatted_log(self, operator: str, text: str):
        lines = text.split('\n')

        with open(self.logfile, "a") as log:
            for line in lines:
                log.write(f"[{operator}] {line}\n")


    def log(self, text: str):
        """
        Creates a log entry.
        Supports multiple lines.

        Parameters:
            text (str): The contents of the log entry.
        """
        self.__write_formatted_log(
            f"{self.format.ORANGE}*{self.format.NC}",
            text
        )

    def add_finding(self, description: str):
        """
        Creates a log entry.
        Supports multiple lines.

        Parameters:
            description (str): A description of the finding.
        """
        self.findings.append(description)
        self.__write_formatted_log(
            f"{self.format.GREEN}F{len(self.findings)}{self.format.NC}",
            description
        )

    def panic(self, description: str):
        """
        Formats and logs error messages.
        Does NOT terminate the script.
        Supports multiple lines.

        Parameters:
            description (str): A description of the error or an error message.
        """
        self.__write_formatted_log(
            f"{self.format.RED}!{self.format.NC}",
            description
        )


def setup_module(argv: list, env: _Environ):
    """
    Creates a new emba module wrapper.

    Parameters:
        argv (list): The list of arguments used to start the Python process.
        env (_Environ): The environment variables of the Python process.

    Returns:
        A new EmbaModule class instance.
    """
    return EmbaModule(argv, env)


def shutdown_module(module: EmbaModule):
    """
    Shut down an emba python module.
    This will also print the amount of findings as an
    interger so EMBA can parse the number.

    Parameters:
        module (EmbaModule): A class instance of EmbaModule.

    Returns:
        none
    """
    print(f"FINDINGS:{len(module.findings)}", end="")
    del module

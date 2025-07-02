#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Code Guidelines:
# -----------------------------
# Indentation should be 2 spaces (no tab character).
# Comments: use # sign followed by a space. When needed, create a comment block. Blank lines: allowed.
# All functions use snake_case (e.g. test_xyz()). One blank lines between functions.
# Variables should be capitalized, with underscore as word separator (e.g. FILE_EXISTS=1).
# If you use external code, add '# Test source: [LINK TO CODE]' above. Ensure we do not run into licensing issues.
# Use 'local' for variables if possible for better resource management and start the name of your variable with a
# lower case l (e.g., local lVARIABLE="asdf")
# Use 'export' for variables which aren't only used in one file - it isn't necessary, but helps for readability

# The following template should be used for the module documenation
# Use a : NOOP and here document to embed documentation,
# The documentation can be generated with the following command:
# perl -ne "s/^\t+//; print if m/END_OF_DOCS'?\$/ .. m/^\s*'?END_OF_DOCS'?\$/ and not m/END_OF_DOCS'?$/;" modules/template_module.sh
# or with pod2text modules/template_module.sh
: <<'END_OF_DOCS'
=pod

=head1 MODULE_NAME

==head2 MODULE_NAME Short description

Please write a short description of your module. Usually ~2-3 sentences are fine to get an idea.

==head2 MODULE_NAME Detailed description

Please write a longer description of your module. This should also include further references and links
that were used.

==head2 MODULE_NAME 3rd party tools

Any 3rd party tool that is needed from your module. Also include the tested and known working version and
download link.

==head2 MODULE_NAME Testfirmware

For verification of the module we need some testfirmware.

Testfirmware details:
- Name:
- Vendor:
- Checksum (MD5/SHA1/SHA256):
- Download Link:

==head2 MODULE_NAME Output

Example output of module

==head2 MODULE_NAME License

EMBA module MODULE_NAME is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only
Link to license document: https://github.com/e-m-b-a/emba/blob/master/LICENSE
Note: Only GPL-3.0 will be accepted in the master EMBA repository

==head2 MODULE_NAME Todo

Missing stuff that we need to consider.

==head2 MODULE_NAME Known issues

Any known issues or known limitations.

==head2 MODULE_NAME Author(s)

Michael Messner, Pascal Eckmann
Note: List all authors including contributors to this module

=cut

END_OF_DOCS


template_module() {
  # Initialize module and creates a log file "template_module_log.txt" and directory "template_module" (if needed) in your log folder
  # Required!
  module_log_init "${FUNCNAME[0]}"
  # Prints title to CLI and into log
  # Required!
  module_title "Empty module"

  # Global variables

    # $FIRMWARE_PATH - absolute path to the root directory of the firmware (String)
    # $FILE_ARR - all valid files of the provided firmware (Array)
    # $BINARIES - all executable binaries of the provided firmware (Array)

  # Setup variables

  local lTESTVAR1=""
  local lTESTVAR2=""

  print_output "[*] TESTVAR1: ${lTESTVAR1}"
  print_output "[*] TESTVAR2: ${lTESTVAR2}"

  # Prints everything to CLI, more information in function print_examples
  print_output "[*] Empty module output"

  # Call a submodule inside of module with a parameter
  sub_module "${lTESTVAR1}"

  # How to use print_output
  print_examples

  # How to use paths inside of project
  path_handling

  # Get all binaries from firmware and use them
  iterate_binary

  # Add links to webreport
  webreport_functions

  # Load stuff from external config files (get list of lines, grep and find)
  load_from_config

  # Usage of `find`: add "${EXCL_FIND[@]}" to exclude all paths (added with '-e' parameter)
  print_output "$(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l)"

  # Ends module and saves status into log - $COUNT_FINDINGS has to be replaced by a number of your findings. If your module didn't found something, then it isn't needed to be generated in the final report
  # Required!
  module_end_log "${FUNCNAME[0]}" "${#COUNT_FINDINGS[@]}"
}

sub_module() {
  # setup local lTESTVAR1_ in function
  local lTESTVAR1_="${1:-}"
  # Create submodules inside of a module for better structure
  sub_module_title "Submodule example"

  print_output "[*] local TESTVAR1_: ${lTESTVAR1_}"

  # Analyze stuff ...
}

print_examples() {
  # Works like 'echo', but with some twists
  print_output "print example"

  # -> if you use 'print_output, it will write into defined (module_log_init) log file'
  # Don't want to log: Add "no_log" as second parameter
  print_output "no log example" "no_log"

  # Automatic color coding (don't add something before '[' - if you need a new line before, use 'echo'):

  # [*] is for informative messages
  print_output "[*] Information example"

  # [+] is for finding messages
  print_output "[*] Finding example"

  # [-] is for failure/no finding messages
  print_output "[-] Not found example"

  # [!] is for warning messages
  print_output "[!] Something went horribly wrong"

  # Functions to change text

  # indent text, e.g. "    indented text example" - works for multiple lines too, if you only use single lines, you can also use "print_output "    indented text example" "
  print_output "$(indent "indented text example")"

  # color text
  print_output "$(orange "orange text example")"
  print_output "$(red "red text example")"
  print_output "$(blue "blue text example")"
  print_output "$(cyan "cyan text example")"
  print_output "$(green "green text example")"
  print_output "$(magenta "magenta text example")"
  print_output "$(white "unformatted text example")" # remove formatting

  # format text
  print_output "$(bold "bold text example")"
  print_output "$(italic "italic text example")"

  # Combination of above functions
  # indent orange text
  print_output "$(indent "$(orange "indented orange text example")")"

  # Good to know: All these functions are also working with text with line breaks

  # If you only want to print stuff into an own log file
  print_log "log text" "[path to log file]" "g"
  # "g" is optional for printing line into grep-able log file (emba -g)
}

path_handling() {
  # Firmware path - use this variable:
  print_output "${FIRMWARE_PATH}"

  # Print paths (standardized) with permissions and owner
  # e.g. /home/linux/firmware/var/etc (drwxr-xr-x firmware firmware)
  print_output "$(print_path "/test/path/file.xy")"

  # Get only permission of path
  permission_clean "/test/path/file.xy"

  # Get only owner of path
  owner_clean "/test/path/file.xy"

  # Get only group of path
  group_clean "/test/path/file.xy"

  # Before using a path in your module!
  # Option 1: Search with find and loop trough results / don't use mod_path!
  # Insert "${EXCL_FIND[@]}" in your search-command to automatically remove excluded paths
  local lCHECK=0
  local lTEST_ARR=()
  readarray -t lTEST_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname '*xy*' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  local lTEST_E=""
  for lTEST_E in "${lTEST_ARR[@]}"; do
    if [[ -f "${lTEST_E}" ]] ; then
      lCHECK=1
      print_output "[+] Found ""$(print_path "${lTEST_E}")"
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No modprobe.d directory found"
  fi

  # Using static single path (mod_path -> returns array of paths, especially if etc is in this path: all other found etc
  # locations will be added there
  # Add placeholder "ETC_PATHS" instead of path "etc"
  lCHECK=0
  local lTEST_PATHS_ARR=()
  mapfile -t lTEST_PATHS_ARR < <(mod_path "/ETC_PATHS/xy.cfg")

  for lTEST_E in "${lTEST_PATHS_ARR[@]}" ; do
    if [[ -f "${lTEST_E}" ]] ; then
      lCHECK=1
      print_output "[+] Found xy config: ""$(print_path "${lTEST_E}")"
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] No xy configuration file found"
  fi

  # Using multiple paths as array:
  local lTEST_PATHS_ARR=()
  mapfile -t lTEST_PATHS_ARR < <(mod_path_array "$(config_list "${CONFIG_DIR}""/test_files.cfg" "")")

  if [[ "${lTEST_PATHS_ARR[0]}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#lTEST_PATHS_ARR[@]}" -ne 0 ]] ; then
    for lTEST_E in "${lTEST_PATHS_ARR[@]}"; do
      if [[ -f "${lTEST_E}" ]] ; then
        print_output "[+] Found: ""$(print_path "${lTEST_E}")"
      fi
    done
  else
    print_output "[-] Nothing found"
  fi
}

iterate_binary() {
  # BINARIES is a global array, which is project wide available and contains all paths of binary files
  local lBIN_FILE=""

  for lBIN_FILE in "${BINARIES[@]}"; do
    print_output "${lBIN_FILE}"
  done
}

webreport_functions() {
  # add a link in the webreport for the printed line to module (e.g. s42) - use the prefix of the module names
  print_output "[*] Information"
  write_link "s42"

  # add anchor to this module, if this module is s42_....sh ...
  write_anchor "test"

  # ... then it can be called by following link
  print_output "This should link to test anchor"
  write_link "s42#test"

  # add a png picture
  write_link "PATH_TO_PNG"

  # add custom log files to webreport
  write_link "PATH_TO_TXT/LOG_FILE"
  # it will be generated and linked with the text of the previous line
}

load_from_config() {
  # config_grep.cfg contains grep statements, these will be all used for grepping "${FILE_PATH}"
  local lOUTPUT=""
  local lOUTPUT_LINES_ARR=()
  mapfile -t lOUTPUT_LINES_ARR < <(config_grep "${CONFIG_DIR}""/config_grep.cfg" "${FILE_PATH}")

  if [[ "${lOUTPUT_LINES_ARR[0]}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#lOUTPUT_LINES_ARR[@]}" -ne 0 ]] ; then
    # count of results
    print_output "[+] Found ""${#lOUTPUT_LINES_ARR[@]}"" files:"

    for lOUTPUT in "${lOUTPUT_LINES_ARR[@]}"; do
      if [[ -f "${lOUTPUT}" ]] ; then
        print_output "$(print_path "${lOUTPUT}")"
      fi
    done
  else
    print_output "[-] Nothing found"
  fi

  # config_list.cfg contains text, you get an array
  local lOUTPUT_LINES_ARR=()
  mapfile -t lOUTPUT_LINES_ARR < <(config_list "${CONFIG_DIR}""/config_list.cfg")

  if [[ "${lOUTPUT_LINES_ARR[0]}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#lOUTPUT_LINES_ARR[@]}" -ne 0 ]] ; then
    # count of results
    print_output "[+] Found ""${#lOUTPUT_LINES_ARR[@]}"" files:"

    for lOUTPUT in "${lOUTPUT_LINES_ARR[@]}"; do
      if [[ -f "${lOUTPUT}" ]] ; then
        print_output "$(print_path "${lOUTPUT}")"
      fi
    done
  else
    print_output "[-] Nothing found"
  fi

  # Find files with search parameters (wildcard * is allowed)
  local lOUTPUT_LINES_ARR=()
  local lLINE=""
  readarray -t lOUTPUT_LINES_ARR < <(printf '%s' "$(config_find "${CONFIG_DIR}""/config_find.cfg")")

  if [[ "${lOUTPUT_LINES_ARR[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#lOUTPUT_LINES_ARR[@]} -ne 0 ]] ; then
    print_output "[+] Found ""${#lOUTPUT_LINES_ARR[@]}"" files:"
    for lLINE in "${lOUTPUT_LINES_ARR[@]}" ; do
      if [[ -f "${lLINE}" ]] ; then
        print_output "$(indent "$(orange "$(print_path "${lLINE}")")")"
      fi
    done
  else
    print_output "[-] No files found"
  fi
}


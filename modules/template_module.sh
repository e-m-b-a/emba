#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Code Guidelines:
# -----------------------------
# Identation should be 2 spaces (no tab character).
# Comments: use # sign followed by a space. When needed, create a comment block. Blank lines: allowed.
# All functions use snake_case (e.g. test_xyz()). One blank lines between functions.
# Variables should be capitalized, with underscore as word separator (e.g. FILE_EXISTS=1).
# If you use external code, add '# Test source: [LINK TO CODE]' above.
# Use 'local' for variables if possible for better resource management
# Use 'export' for variables which aren't only used in one file - it isn't necessary, but helps for readability
# Boolean: 0=False 1=True, e.g. [[ $VAR -eq 0 ]]

empty_module() {
  # Initialize module and creates a log file "empty_module_log.txt" in your log folder
  module_log_init "${FUNCNAME[0]}"
  # Prints title to CLI and into log
  module_title "Empty module"

  # Prints everything to CLI, more information in function print_examples
  print_output "[*] Empty module output"

  # Submodule inside of module - only for better structure
  sub_module

  # How to use print_output
  print_examples

  # How to use paths inside of project
  path_handling

  # Get all binaries from firmware and use them
  iterate_binary

  # Load stuff from external config files (get list of lines, grep and find)
  load_from_config

  # - Usage of `find`: add "${EXCL_FIND[@]}" to exclude all paths (added with '-e' parameter)
  print_output "$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l)"
}

sub_module() {
  # Create submodules inside of a module for better structure
  sub_module_title "Submodule example"

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

  # indent text, e.g. "    indented text example"
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
  # "g" is optional for printing line into grep-able log file (emba.sh -g)
}

path_handling() {
  # Firmware path - use this variable:
  print_output "$FIRMWARE_PATH"

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
  CHECK=0
  readarray -t TEST < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname '*xy*' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  for TEST_E in "${TEST[@]}"; do
    if [[ -f "$MP_DIR" ]] ; then
      CHECK=1
      print_output "[+] Found ""$(print_path "$TEST_E")"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No modprobe.d directory found"
  fi

  # Using static single path (mod_path -> returns array of paths, especially if etc is in this path: all other found etc
  # locations will be added there
  # Add placeholder "ETC_PATHS" instead of path "etc"
  CHECK=0
  mapfile -t TEST_PATHS < <(mod_path "/ETC_PATHS/xy.cfg")

  for TEST_E in "${TEST_PATHS[@]}" ; do
    if [[ -f "$TEST_E" ]] ; then
      CHECK=1
      print_output "[+] Found xy config: ""$(print_path "$TEST_E")"
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No xy configuration file found"
  fi

  # Using multiple paths as array:
  mapfile -t TEST_PATHS_ARR < <(mod_path_array "$(config_list "$CONFIG_DIR""/test_files.cfg" "")")

  if [[ "${TEST_PATHS_ARR[0]}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#TEST_PATHS_ARR[@]}" -ne 0 ]] ; then
    for TEST_E in "${TEST_PATHS_ARR[@]}"; do
      if [[ -f "$TEST_E" ]] ; then
        print_output "[+] Found: ""$(print_path "$TEST_E")"
      fi
    done
  else
    print_output "[-] Nothing found"
  fi
}

iterate_binary() {
  # BINARIES is an array, which is project wide available and contains all paths of binary files
  for BIN_FILE in "${BINARIES[@]}"; do
    print_output "$BIN_FILE"
  done
}

load_from_config() {
  # config_grep.cfg contains grep statements, these will be all used for grepping "$FILE_PATH"
  mapfile -t OUTPUT_LINES < <(config_grep "$CONFIG_DIR""/config_grep.cfg" "$FILE_PATH")

  if [[ "${OUTPUT_LINES[0]}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#OUTPUT_LINES[@]}" -ne 0 ]] ; then
    # count of results
    print_output "[+] Found ""${#OUTPUT_LINES[@]}"" files:"

    for OUTPUT in "${OUTPUT_LINES[@]}"; do
      if [[ -f "$OUTPUT" ]] ; then
        print_output "$(print_path "$OUTPUT")"
      fi
    done
  else
    print_output "[-] Nothing found"
  fi


  # config_list.cfg contains text, you get an array
  mapfile -t OUTPUT_LINES < <(config_list "$CONFIG_DIR""/config_list.cfg")

  if [[ "${OUTPUT_LINES[0]}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#OUTPUT_LINES[@]}" -ne 0 ]] ; then
    # count of results
    print_output "[+] Found ""${#OUTPUT_LINES[@]}"" files:"

    for OUTPUT in "${OUTPUT_LINES[@]}"; do
      if [[ -f "$OUTPUT" ]] ; then
        print_output "$(print_path "$OUTPUT")"
      fi
    done
  else
    print_output "[-] Nothing found"
  fi


  # Find files with search parameters (wildcard * is allowed)
  local OUTPUT_LINES
  readarray -t OUTPUT_LINES < <(printf '%s' "$(config_find "$CONFIG_DIR""/config_find.cfg")")

  if [[ "${OUTPUT_LINES[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#OUTPUT_LINES[@]} -ne 0 ]] ; then
    print_output "[+] Found ""${#OUTPUT_LINES[@]}"" files:"
    for LINE in "${OUTPUT_LINES[@]}" ; do
      if [[ -f "$LINE" ]] ; then
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      fi
    done
  else
    print_output "[-] No files found"
  fi
}


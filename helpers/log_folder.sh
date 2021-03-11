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

# Description:  Check for log directory

log_folder()
{
  if [[ $ONLY_DEP -eq 0 ]] && [[ -d "$LOG_DIR" ]] ; then
    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    There are files in the specified directory: ""$LOG_DIR""\\n    You can now delete the content here or start the tool again and specify a different directory."
    echo -e "\\n${ORANGE}Delete content of log directory: $LOG_DIR ?${NC}\\n"
    read -p "(Y/n)  " -r ANSWER
    case ${ANSWER:0:1} in
        y|Y|"" )
          if mount | grep "$LOG_DIR" | grep -e "proc\|sys\|run" > /dev/null; then
            echo
            print_output "[!] We found unmounted areas from a former emulation process in your log directory $LOG_DIR." "no_log"
            print_output "[!] You should unmount this stuff manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "$LOG_DIR")")" "no_log"
            echo -e "\\n${RED}Terminate emba${NC}\\n"
            exit 1
          elif mount | grep "$LOG_DIR" > /dev/null; then
            echo
            print_output "[!] We found unmounted areas in your log directory $LOG_DIR." "no_log"
            print_output "[!] If emba is failing check this manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "$LOG_DIR")")" "no_log"
          else
            rm -R "${LOG_DIR:?}/"*
            echo -e "\\n${GREEN}Sucessfully deleted: $LOG_DIR ${NC}\\n"
          fi
        ;;
        * )
          echo -e "\\n${RED}Terminate emba${NC}\\n"
          exit 1
        ;;
    esac
  fi
}

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

  readarray -t D_LOG_FILES < <( find . \( -path ./external -o -path ./config \) -prune -false -o -name "*.txt" -o -name "*.log" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  if [[ $USE_DOCKER -eq 1 && ${#D_LOG_FILES[@]} -gt 0 ]] ; then
    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    It appears that there are log files in the emba directory.\\n    You should move these files to another location where they won't be exposed to the Docker container."
    for D_LOG_FILE in "${D_LOG_FILES[@]}" ; do
      echo -e "        ""$(print_path "$D_LOG_FILE")"
    done
    echo -e "\\n${ORANGE}Continue to run emba and ignore this warning?${NC}\\n"
    read -p "(Y/n)  " -r ANSWER
    case ${ANSWER:0:1} in
        y|Y|"" )
        ;;
        * )
          echo -e "\\n${RED}Terminate emba${NC}\\n"
          exit 1
        ;;
    esac
  fi
}

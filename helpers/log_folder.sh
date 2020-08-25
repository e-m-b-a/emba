#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
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
    read -p "(y/n)  " -r ANSWER
    case ${ANSWER:0:1} in
        y|Y|"" )
          rm -R "${LOG_DIR:?}/"*
          echo -e "\\n${GREEN}Sucessfully deleted: $LOG_DIR ${NC}\\n"
        ;;
        * )
          echo -e "\\n${RED}Terminate emba${NC}\\n"
          exit 1
        ;;
    esac
  fi
}

#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Installs Android apk analysis tool APKhunt

I17_apk_check() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    print_tool_info "golang-go" 1
    print_tool_info "jadx" 1
    print_tool_info "dex2jar" 1
    print_tool_info "apktool" 1
    print_git_info "APKHunt" "EMBA-support-repos/APKHunt" "APKHunt | OWASP MASVS Static Analyzer"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""These applications (if not already on the system) will be downloaded!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        git clone https://github.com/EMBA-support-repos/APKHunt.git external/APKHunt
      ;;
    esac
  fi
}

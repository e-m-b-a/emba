#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Installs firmadyne full system emulation
#               This is a temporary module which will be removed in the future without any further note!

IL22_firmadyne_system_emulator() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || exit 1

    print_tool_info "busybox-static" 1
    print_tool_info "fakeroot" 1
    print_tool_info "git" 1
    print_tool_info "dmsetup" 1
    print_tool_info "kpartx" 1
    print_tool_info "netcat-openbsd" 1
    print_tool_info "nmap" 1
    print_tool_info "python3-psycopg2" 1
    print_tool_info "snmp" 1
    print_tool_info "uml-utilities" 1
    print_tool_info "util-linux" 1
    print_tool_info "vlan" 1
    print_tool_info "qemu-system-arm" 1
    print_tool_info "qemu-system-mips" 1
    print_tool_info "qemu-system-x86" 1
    print_tool_info "qemu-utils" 1

    print_git_info "Firmadyne system mode emulator" "firmadyne/firmadyne" "FIRMADYNE is an automated and scalable system for performing emulation and dynamic analysis of Linux-based embedded firmware"
    echo -e "\\n""$MAGENTA""$BOLD""This is a temporary module which will be removed in the future without any further note!""$NC"


    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The firmadyne system emulation dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

        apt-get install "${INSTALL_APP_LIST[@]}" -y

        if ! [[ -d external/firmadyne_orig ]]; then
          git clone --recursive https://github.com/firmadyne/firmadyne.git external/firmadyne_orig
          cd external/firmadyne_orig || exit 1
        else
          cd external/firmadyne_orig || exit 1
          git pull
        fi

        # this is already done via IL21 installer
        #apt-get install postgresql
        #sudo -u postgres createuser -P firmadyne
        #sudo -u postgres createdb -O firmadyne firmware
        # shellcheck disable=SC2024
        #sudo -u postgres psql -d firmware < ./firmadyne/database/schema

        # as we are currently using the old binwalk version, we need to downgrade the extractor:
        wget https://raw.githubusercontent.com/firmadyne/extractor/6e05a6a8e5d553da70e27c2a653a40f992378557/extractor.py -O ./extractor/extractor.py

        sed -i "s/^#FIRMWARE_DIR.*/FIRMWARE_DIR=$(pwd)/g" firmadyne.config

        ./download.sh

        cd "$HOME_PATH" || exit 1

      ;;
    esac
  fi
}


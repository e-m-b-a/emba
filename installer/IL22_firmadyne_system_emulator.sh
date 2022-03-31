#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Installs firmadyne / full system emulation
#               This is a temporary module which will be removed in the future without any further note!

IL22_firmadyne_system_emulator() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || exit 1

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

        apt-get install busybox-static fakeroot git dmsetup kpartx netcat-openbsd nmap python3-psycopg2 snmp uml-utilities util-linux vlan

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

        ./download.sh

        apt-get install qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils

        cd "$HOME_PATH" || exit 1

      ;;
    esac
  fi
}


#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Installs basic extractor tools

IP00_extractors(){
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]] ; then

    print_tool_info "python3-pip" 1
    print_tool_info "patool" 1
    print_pip_info "bsdiff4"
    print_git_info "payload_dumper" "EMBA-support-repos/payload_dumper" "Android OTA payload.bin extractor"
    print_git_info "smcbmc" "EMBA-support-repos/smcbmc" "Supermicro BMC firmware image decryptor"
    print_git_info "dji-firmware-tools" "EMBA-support-repos/dji-firmware-tools" "Tools for extracting, modding and re-packaging firmwares of DJI multirotor drones."
    print_tool_info "python3-pycryptodome" 1
    # sometimes the python pip installation is needed - probably this will be solved in the future
    # probably it depends on the venv?!?
    print_pip_info "pycryptodome"
    # ubireader:
    # print_tool_info "python3-lzo" 1
    print_tool_info "liblzo2-dev" 1
    print_pip_info "python-lzo"
    # vmdk extractor:
    print_tool_info "guestfs-tools" 1
    # payload_dumper:
    print_pip_info "fsspec"
    # Buffalo decryptor
    print_file_info "buffalo-enc.c" "Decryptor for Buffalo firmware images" "https://git-us.netdef.org/projects/OSR/repos/openwrt-buildroot/raw/tools/firmware-utils/src/buffalo-enc.c" "external/buffalo-enc.c"
    print_file_info "buffalo-lib.c" "Decryptor for Buffalo firmware images" "https://git-us.netdef.org/projects/OSR/repos/openwrt-buildroot/raw/tools/firmware-utils/src/buffalo-lib.c" "external/buffalo-lib.c"
    print_file_info "buffalo-lib.h" "Decryptor for Buffalo firmware images" "https://git-us.netdef.org/projects/OSR/repos/openwrt-buildroot/raw/tools/firmware-utils/src/buffalo-lib.h" "external/buffalo-lib.h"
    print_tool_info "gcc" 1
    print_tool_info "libc6-dev" 1
    print_tool_info "mtd-utils" 1

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""These applications will be installed/updated!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        echo

        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
        pip_install "setuptools" "-U"
        pip_install "wheel" "-U"
        pip_install "bsdiff4"
        pip_install "python-lzo>=1.14"
        pip_install "pycryptodome"
        pip_install "fsspec"

        if ! [[ -d external/payload_dumper ]]; then
          git clone https://github.com/EMBA-support-repos/payload_dumper.git external/payload_dumper
        else
          cd external/payload_dumper || ( echo "Could not install EMBA component payload dumper" && exit 1 )
          git pull
          cd "${HOME_PATH}" || ( echo "Could not install EMBA component payload dumper" && exit 1 )
        fi

        if ! [[ -d external/smcbmc ]]; then
          git clone https://github.com/EMBA-support-repos/smcbmc.git external/smcbmc
        else
          cd external/smcbmc || ( echo "Could not install EMBA component smcbmc" && exit 1 )
          git pull
          cd "${HOME_PATH}" || ( echo "Could not install EMBA component smcbmc" && exit 1 )
        fi

        if ! [[ -d external/dji-firmware-tools ]]; then
          git clone https://github.com/EMBA-support-repos/dji-firmware-tools.git external/dji-firmware-tools
        else
          cd external/dji-firmware-tools || ( echo "Could not install EMBA component dji-firmware-tools" && exit 1 )
          git pull
          cd "${HOME_PATH}" || ( echo "Could not install EMBA component dji-firmware-tools" && exit 1 )
        fi

        if ! [[ -f "./external/buffalo-enc.elf" ]] ; then
          # Buffalo decryptor:
          download_file "buffalo-enc.c" "https://git-us.netdef.org/projects/OSR/repos/openwrt-buildroot/raw/tools/firmware-utils/src/buffalo-enc.c" "external/buffalo-enc.c"
          download_file "buffalo-lib.c" "https://git-us.netdef.org/projects/OSR/repos/openwrt-buildroot/raw/tools/firmware-utils/src/buffalo-lib.c" "external/buffalo-lib.c"
          download_file "buffalo-lib.h" "https://git-us.netdef.org/projects/OSR/repos/openwrt-buildroot/raw/tools/firmware-utils/src/buffalo-lib.h" "external/buffalo-lib.h"
          cd ./external || ( echo "Could not install EMBA component buffalo decryptor" && exit 1 )
          sed -i 's/#include "buffalo-lib.h"/#include "buffalo-lib.h"\n#include "buffalo-lib.c"/g' buffalo-enc.c
          gcc -o buffalo-enc.elf buffalo-enc.c
          rm buffalo-enc.c buffalo-lib.c buffalo-lib.h
          cd "${HOME_PATH}" || ( echo "Could not install EMBA component buffalo decryptor" && exit 1 )

        fi
        if [[ -f "./external/buffalo-enc.elf" ]] ; then
          echo -e "${GREEN}""Buffalo decryptor installed successfully""${NC}"
        else
          echo -e "${ORANGE}""Buffalo decryptor installation failed - check it manually""${NC}"
        fi
      ;;
    esac
  fi
}

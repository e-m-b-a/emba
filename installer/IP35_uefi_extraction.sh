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
# Author(s): Benedikt Kuehne

# Description:  Installs UEFIExtract from https://github.com/LongSoft/UEFITool/releases
#               into external/UEFITool/UEFIExtract

IP35_uefi_extraction() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    INSTALL_APP_LIST=()

    print_file_info "UEFIExtract_NE_A62_linux_x86_64.zip" "Release-version A62" "https://github.com/LongSoft/UEFITool/releases/download/A62/UEFIExtract_NE_A62_linux_x86_64.zip" "external/UEFITool/UEFIExtract_NE_A62_linux_x86_64.zip"
    print_tool_info "unzip" 1
    print_pip_info "uefi_firmware"
    print_pip_info "biosutilities"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]]; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""UEFI Extraction Tool"" will be downloaded (if not already on the system) installed!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
        pip_install "uefi_firmware"
        pip_install "biosutilities"

        if ! [[ -d external/UEFITool ]]; then
          mkdir external/UEFITool
        fi
        download_file "UEFIExtract_NE_A62_linux_x86_64.zip" "https://github.com/LongSoft/UEFITool/releases/download/A62/UEFIExtract_NE_A62_linux_x86_64.zip" "external/UEFITool/UEFIExtract_NE_A62_linux_x86_64.zip"
        if [[ -f "external/UEFITool/UEFIExtract_NE_A62_linux_x86_64.zip" ]]; then
          if ! [[ -f external/UEFITool/UEFIExtract ]]; then
            unzip external/UEFITool/UEFIExtract_NE_A62_linux_x86_64.zip -d external/UEFITool
          fi
        else
          echo -e "${ORANGE}""UEFITool installation failed - check it manually""${NC}"
        fi
        ;;
    esac
  fi
}

#!/bin/bash

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
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs yara rules

I110_yara_check() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    INSTALL_APP_LIST=()

    print_tool_info "yara" 1

    print_file_info "Xumeiquer/yara-forensics/compressed.yar" "" "https://raw.githubusercontent.com/Xumeiquer/yara-forensics/master/file/compressed.yar" "external/yara/compressed.yar"
    print_file_info "DiabloHorn/yara4pentesters/juicy_files.txt" "" "https://raw.githubusercontent.com/DiabloHorn/yara4pentesters/master/juicy_files.txt" "external/yara/juicy_files.yar"
    print_file_info "ahhh/YARA/crypto_signatures.yar" "" "https://raw.githubusercontent.com/ahhh/YARA/master/crypto_signatures.yar" "external/yara/crypto_signatures.yar"
    print_file_info "Yara-Rules/rules/packer_compiler_signatures.yar" "" "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer_compiler_signatures.yar" "external/yara/packer_compiler_signatures.yar"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""These rules (if not already on the system) will be downloaded!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        if ! [[ -d "external/yara/" ]] ; then
          mkdir external/yara
        fi

        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        download_file "Xumeiquer/yara-forensics/compressed.yar" "https://raw.githubusercontent.com/Xumeiquer/yara-forensics/master/file/compressed.yar" "external/yara/compressed.yar"
        download_file "DiabloHorn/yara4pentesters/juicy_files.txt" "https://raw.githubusercontent.com/DiabloHorn/yara4pentesters/master/juicy_files.txt" "external/yara/juicy_files.yar"
        download_file "ahhh/YARA/crypto_signatures.yar" "https://raw.githubusercontent.com/ahhh/YARA/master/crypto_signatures.yar" "external/yara/crypto_signatures.yar"
        download_file "Yara-Rules/rules/packer_compiler_signatures.yar" "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer_compiler_signatures.yar" "external/yara/packer_compiler_signatures.yar"
      ;;
    esac
  fi
}

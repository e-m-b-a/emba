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

# Description:  Installs vmlinux-to-elf - https://github.com/marin-m/vmlinux-to-elf

I24_25_kernel_tools() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then

    print_tool_info "python3-pip" 1
    print_tool_info "flex"
    print_tool_info "pahole"
    print_tool_info "bison"
    print_tool_info "pkg-config"
    print_pip_info "python-lzo"
    print_git_info "kconfig-hardened-check" "EMBA-support-repos/kconfig-hardened-check" "There are plenty of security hardening options for the Linux kernel. This tool checks them."

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""These applications (if not already on the system) will be downloaded!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
        if ! [[ -d external/vmlinux-to-elf ]]; then
          git clone https://github.com/EMBA-support-repos/vmlinux-to-elf external/vmlinux-to-elf
        fi

        cd external/vmlinux-to-elf || ( echo "Could not install EMBA component vmlinux-to-elf" && exit 1 )
        pip_install "git+https://github.com/EMBA-support-repos/vmlinux-to-elf" -U
        pip_install "python-lzo>=1.14"
        cd "${HOME_PATH}" || ( echo "Could not install EMBA component vmlinux-to-elf" && exit 1 )

        if ! [[ -d external/kconfig-hardened-check ]]; then
          git clone https://github.com/EMBA-support-repos/kconfig-hardened-check.git external/kconfig-hardened-check
        fi
      ;;
    esac
  fi
}

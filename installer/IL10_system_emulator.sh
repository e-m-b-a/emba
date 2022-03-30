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
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs firmadyne / full system emulation

IL10_system_emulator() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "$HOME_PATH" || exit 1

    print_tool_info "busybox-static" 1
    print_tool_info "bash-static" 1
    print_tool_info "fakeroot" 1
    print_tool_info "git" 1
    print_tool_info "dmsetup" 1
    print_tool_info "kpartx" 1
    print_tool_info "uml-utilities" 1
    print_tool_info "util-linux" 1
    print_tool_info "vlan" 1
    print_tool_info "qemu-system-arm" 1
    print_tool_info "qemu-system-mips" 1
    print_tool_info "qemu-system-x86" 1
    print_tool_info "qemu-utils" 1

    print_file_info "vmlinux.mipsel" "Firmadyne - Linux kernel 2.6 - MIPSel" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel" "external/firmadyne/binaries/vmlinux.mipsel"
    print_file_info "vmlinux.mipseb" "Firmadyne - Linux kernel 2.6 - MIPSeb" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb" "external/firmadyne/binaries/vmlinux.mipseb"
    print_file_info "zImage.armel" "Firmadyne - Linux kernel 4.1 - ARMel" "https://github.com/firmadyne/kernel-v4.1/releases/download/v1.1/zImage.armel" "external/firmadyne/binaries/zImage.armel"
    print_file_info "console.armel" "Firmadyne - Console - ARMel" "https://github.com/firmadyne/console/releases/download/v1.0/console.armel" "external/firmadyne/binaries/console.armel"
    print_file_info "console.mipseb" "Firmadyne - Console - MIPSeb" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipseb" "external/firmadyne/binaries/console.mipseb"
    print_file_info "console.mipsel" "Firmadyne - Console - MIPSel" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipsel" "external/firmadyne/binaries/console.mipsel"
    print_file_info "libnvram.so.armel" "Firmadyne - libnvram - ARMel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.armel" "external/firmadyne/binaries/libnvram.so.armel"
    print_file_info "libnvram.so.mipseb" "Firmadyne - libnvram - MIPSeb" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipseb" "external/firmadyne/binaries/libnvram.so.mipseb"
    print_file_info "libnvram.so.mipsel" "Firmadyne - libnvram - MIPSel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipsel" "external/firmadyne/binaries/libnvram.so.mipsel"
    print_file_info "fixImage.sh" "Firmadyne fixImage script" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/fixImage.sh" "external/firmadyne/scripts/"
    print_file_info "preInit.sh" "Firmadyne preInit script" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/preInit.sh" "external/firmadyne/scripts/"

    echo -e "\\n""$MAGENTA""$BOLD""This is a deprecated module which will be removed in the future without any further note!""$NC"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The firmadyne dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

      mkdir -p external/firmadyne/binaries
      mkdir -p external/firmadyne/binaries_FirmAE
      mkdir -p external/firmadyne/scripts

      apt-get install "${INSTALL_APP_LIST[@]}" -y

      # Firmadyne stuff:
      if ! [[ -f "external/firmadyne/binaries/vmlinux.mipsel" ]]; then
        download_file "vmlinux.mipsel" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel" "external/firmadyne/binaries/vmlinux.mipsel"
      else
        echo -e "$GREEN""vmlinux.mipsel already installed""$NC"
      fi

      if ! [[ -f "external/firmadyne/binaries/vmlinux.mipseb" ]]; then
        download_file "vmlinux.mipseb" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb" "external/firmadyne/binaries/vmlinux.mipseb"
      else
        echo -e "$GREEN""vmlinux.mipseb already installed""$NC"
      fi

      if ! [[ -f "external/firmadyne/binaries/zImage.armel" ]]; then
        download_file "zImage.armel" "https://github.com/firmadyne/kernel-v4.1/releases/download/v1.1/zImage.armel" "external/firmadyne/binaries/zImage.armel"
      else
        echo -e "$GREEN""zImage.armel already installed""$NC"
      fi

      if ! [[ -f "external/firmadyne/binaries/console.armel" ]]; then
        download_file "console.armel" "https://github.com/firmadyne/console/releases/download/v1.0/console.armel" "external/firmadyne/binaries/console.armel"
      else
        echo -e "$GREEN""console.armel already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/console.mipseb" ]]; then
        download_file "console.mipseb" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipseb" "external/firmadyne/binaries/console.mipseb"
      else
        echo -e "$GREEN""console.mipseb already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/console.mipsel" ]]; then
        download_file "console.mipsel" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipsel" "external/firmadyne/binaries/console.mipsel"
      else
        echo -e "$GREEN""console.mipsel already installed""$NC"
      fi

      if ! [[ -f "external/firmadyne/binaries/libnvram.so.armel" ]]; then
        download_file "libnvram.so.armel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.armel" "external/firmadyne/binaries/libnvram.so.armel"
      else
        echo -e "$GREEN""libnvram.so.armel already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/libnvram.so.mipseb" ]]; then
        download_file "libnvram.so.mipseb" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipseb" "external/firmadyne/binaries/libnvram.so.mipseb"
      else
        echo -e "$GREEN""libnvram.so.mipseb already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/libnvram.so.mipsel" ]]; then
        download_file "libnvram.so.mipsel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipsel" "external/firmadyne/binaries/libnvram.so.mipsel"
      else
        echo -e "$GREEN""libnvram.so.mipsel already installed""$NC"
      fi

      if ! [[ -f "external/firmadyne/scripts/fixImage_firmadyne.sh" ]]; then
        download_file "fixImage.sh" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/fixImage.sh" "external/firmadyne/scripts/fixImage_firmadyne.sh"
      else
        echo -e "$GREEN""firmadyne fixImage.sh already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/scripts/preInit_firmadyne.sh" ]]; then
        download_file "preInit.sh" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/preInit.sh" "external/firmadyne/scripts/preInit_firmadyne.sh"
      else
        echo -e "$GREEN""firmadyne preInit.sh already installed""$NC"
      fi

      ;;
    esac
  fi
}


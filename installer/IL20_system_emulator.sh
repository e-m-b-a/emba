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

# Description:  Installs full system emulation dependencies
#               Module is based on FirmAE and firmadyne

IL20_system_emulator() {
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

    # future use:
    print_file_info "vmlinux.mipsel.2" "FirmAE - Linux kernel 2.6 - MIPSel" "https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/v1.0/vmlinux.mipsel.2" "external/firmae/binaries/vmlinux.mipsel.2"
    print_file_info "vmlinux.mipseb.2" "FirmAE - Linux kernel 2.6 - MIPSeb" "https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/v1.0/vmlinux.mipseb.2" "external/firmae/binaries/vmlinux.mipseb.2"
    print_file_info "vmlinux.mipsel.4" "FirmAE - Linux kernel 4.1 - MIPSel" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.mipsel.4" "external/firmae/binaries/vmlinux.mipsel.4"
    print_file_info "vmlinux.mipseb.4" "FirmAE - Linux kernel 4.1 - MIPSeb" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.mipseb.4" "external/firmae/binaries/vmlinux.mipseb.4"

    print_file_info "zImage.armel" "FirmAE - Linux kernel 4.1 - ARMel" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/zImage.armel" "external/firmae/binaries/zImage.armel"
    print_file_info "vmlinux.armel" "FirmAE - Linux kernel 4.1 - ARMel" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.armel" "external/firmae/binaries/vmlinux.armel"

    print_file_info "busybox.armel" "FirmAE - busybox - ARMel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.armel" "external/firmae/binaries/console.armel"
    print_file_info "busybox.mipseb" "FirmAE - busybox - MIPSeb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipseb" "external/firmae/binaries/console.mipseb"
    print_file_info "busybox.mipsel" "FirmAE - busybox - MIPSel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipsel" "external/firmae/binaries/console.mipsel"

    print_file_info "console.armel" "FirmAE - Console - ARMel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.armel" "external/firmae/binaries/console.armel"
    print_file_info "console.mipseb" "FirmAE - Console - MIPSeb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipseb" "external/firmae/binaries/console.mipseb"
    print_file_info "console.mipsel" "FirmAE - Console - MIPSel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipsel" "external/firmae/binaries/console.mipsel"

    print_file_info "libnvram.so.armel" "FirmAE - libnvram - ARMel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.armel" "external/firmae/binaries/libnvram.so.armel"
    print_file_info "libnvram.so.mipseb" "FirmAE - libnvram - MIPSeb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipseb" "external/firmae/binaries/libnvram.so.mipseb"
    print_file_info "libnvram.so.mipsel" "FirmAE - libnvram - MIPSel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipsel" "external/firmae/binaries/libnvram.so.mipsel"
    print_file_info "libnvram_ioctl.so.armel" "FirmAE - libnvram_ioctl - ARMel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.armel" "external/firmae/binaries/libnvram_ioctl.so.armel"
    print_file_info "libnvram_ioctl.so.mipseb" "FirmAE - libnvram_ioctl - MIPSeb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipseb" "external/firmae/binaries/libnvram_ioctl.so.mipseb"
    print_file_info "libnvram_ioctl.so.mipsel" "FirmAE - libnvram_ioctl - MIPSel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipsel" "external/firmae/binaries/libnvram_ioctl.so.mipsel"

    print_file_info "fixImage.sh" "FirmAE fixImage script" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/fixImage.sh" "external/firmae/scripts/"
    print_file_info "preInit.sh" "FirmAE preInit script" "https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/preInit.sh" "external/firmae/scripts/"
    print_file_info "network.sh" "FirmAE network script" "https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/network.sh" "external/firmae/scripts/"
    print_file_info "makeNetwork.sh" "FirmAE makeNetwork script" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/makeNetwork.sh" "external/firmae/scripts/"
    print_file_info "run_service.sh" "FirmAE run_service script" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/run_service.sh" "external/firmae/scripts/"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The system emulation dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

      mkdir -p external/firmae/binaries
      mkdir -p external/firmae/scripts

      apt-get install "${INSTALL_APP_LIST[@]}" -y

      download_file "vmlinux.mipsel.2" "https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/v1.0/vmlinux.mipsel.2" "external/firmae/binaries/vmlinux.mipsel.2"
      download_file "vmlinux.mipseb.2" "https://github.com/pr0v3rbs/FirmAE_kernel-v2.6/releases/download/v1.0/vmlinux.mipseb.2" "external/firmae/binaries/vmlinux.mipseb.2"
      download_file "vmlinux.mipsel.4" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.mipsel.4" "external/firmae/binaries/vmlinux.mipsel.4"
      download_file "vmlinux.mipseb.4" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.mipseb.4" "external/firmae/binaries/vmlinux.mipseb.4"

      download_file "zImage.armel" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/zImage.armel" "external/firmae/binaries/zImage.armel"
      download_file "vmlinux.armel" "https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.armel" "external/firmae/binaries/vmlinux.armel"

      download_file "busybox.armel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.armel" "external/firmae/binaries/console.armel"
      download_file "busybox.mipseb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipseb" "external/firmae/binaries/console.mipseb"
      download_file "busybox.mipsel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/busybox.mipsel" "external/firmae/binaries/console.mipsel"

      download_file "console.armel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.armel" "external/firmae/binaries/console.armel"
      download_file "console.mipseb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipseb" "external/firmae/binaries/console.mipseb"
      download_file "console.mipsel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/console.mipsel" "external/firmae/binaries/console.mipsel"

      download_file "libnvram.so.armel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.armel" "external/firmae/binaries/libnvram.so.armel"
      download_file "libnvram.so.mipseb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipseb" "external/firmae/binaries/libnvram.so.mipseb"
      download_file "libnvram.so.mipsel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram.so.mipsel" "external/firmae/binaries/libnvram.so.mipsel"
      download_file "libnvram_ioctl.so.armel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.armel" "external/firmae/binaries/libnvram_ioctl.so.armel"
      download_file "libnvram_ioctl.so.mipseb" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipseb" "external/firmae/binaries/libnvram_ioctl.so.mipseb"
      download_file "libnvram_ioctl.so.mipsel" "https://github.com/pr0v3rbs/FirmAE/releases/download/v1.0/libnvram_ioctl.so.mipsel" "external/firmae/binaries/libnvram_ioctl.so.mipsel"

      download_file "fixImage.sh" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/fixImage.sh" "external/firmae/scripts/fixImage.sh"
      download_file "preInit.sh" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/preInit.sh" "external/firmae/scripts/preInit.sh"
      download_file "network.sh" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/network.sh" "external/firmae/scripts/network.sh"
      download_file "inferNetwork.sh" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/inferNetwork.sh" "external/firmae/scripts/inferNetwork.sh"
      download_file "run_service.sh" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/scripts/run_service.sh" "external/firmae/scripts/run_service.sh"

      # patch network.sh:
      sed 's/for FILE in `${BUSYBOX} find \/ -name "preinitMT" -o -name "preinit" -o -name "rcS"`/for FILE in `${BUSYBOX} find \/ -name "preinitMT" -o -name "preinit" -o -name "rcS" -o -name "rc.sysinit"`/' external/firmae/scripts/network.sh

      ;;
    esac
  fi
}


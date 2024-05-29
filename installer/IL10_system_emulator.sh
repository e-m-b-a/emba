#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
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

IL10_system_emulator() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "${HOME_PATH}" || ( echo "Could not install EMBA component system emulator" && exit 1 )

    print_tool_info "busybox-static" 1
    print_tool_info "bash-static" 1
    print_tool_info "fakeroot" 1
    print_tool_info "git" 1
    print_tool_info "dmsetup" 1
    print_tool_info "kpartx" 1
    print_tool_info "uml-utilities" 1
    print_tool_info "util-linux" 1
    print_tool_info "vlan" 1
    print_tool_info "qemu-utils" 1
    print_tool_info "qemu-system" 1
    print_tool_info "qemu-system-common" 1
    print_tool_info "qemu-system-arm" 1
    print_tool_info "qemu-system-mips" 1
    print_tool_info "qemu-system-x86" 1
    print_tool_info "qemu-system-ppc" 1
    print_tool_info "qemu-system-misc" 1
    print_tool_info "hping3" 1
    print_tool_info "traceroute" 1

    # future extension
    print_tool_info "xxd" 1
    print_tool_info "netcat-openbsd" 1

    # BusyBox - https://busybox.net/downloads/busybox-1.29.3.tar.bz2
    print_file_info "busybox.armel" "busybox ARMel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armel" "external/EMBA_Live_bins/busybox/busybox.armel"
    print_file_info "busybox.armelhf" "busybox ARMel hard float" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armelhf" "external/EMBA_Live_bins/busybox/busybox.armelhf"
    print_file_info "busybox.arm64el" "busybox ARM64el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.arm64el" "external/EMBA_Live_bins/busybox/busybox.arm64el"
    print_file_info "busybox.mips64n32eb" "busybox mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32eb" "external/EMBA_Live_bins/busybox/busybox.mips64n32eb"
    print_file_info "busybox.mips64n32el" "busybox mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32el" "external/EMBA_Live_bins/busybox/busybox.mips64n32el"
    print_file_info "busybox.mips64r2eb" "busybox mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2eb" "external/EMBA_Live_bins/busybox/busybox.mips64r2eb"
    print_file_info "busybox.mips64r2el" "busybox mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2el" "external/EMBA_Live_bins/busybox/busybox.mips64r2el"
    print_file_info "busybox.mips64v1el" "busybox mips64v1el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64v1el" "external/EMBA_Live_bins/busybox/busybox.mips64v1el"
    print_file_info "busybox.mips64v1eb" "busybox mips64v1eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64v1el" "external/EMBA_Live_bins/busybox/busybox.mips64v1eb"
    print_file_info "busybox.mipseb" "busybox mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipseb" "external/EMBA_Live_bins/busybox/busybox.mipseb"
    print_file_info "busybox.mipsel" "busybox mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipsel" "external/EMBA_Live_bins/busybox/busybox.mipsel"
    print_file_info "busybox.x86el" "busybox x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.x86el" "external/EMBA_Live_bins/busybox/busybox.x86el"

    # Console - https://github.com/EMBA-support-repos/firmadyne-console
    print_file_info "console.zip" "console for all supported architectures" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/console.zip" "external/EMBA_Live_bins/console.zip"
    print_file_info "gdb.zip" "GDB and gdbserver for all supported architectures" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/gdb.zip" "external/EMBA_Live_bins/gdb.zip"
    # libnvram - https://github.com/EMBA-support-repos/FirmAE-libnvram
    print_file_info "libnvram.zip" "libnvram for all supported architectures" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/libnvram.zip" "external/EMBA_Live_bins/libnvram.zip"
    print_file_info "netcat.zip" "netcat for all supported architectures" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/netcat.zip" "external/EMBA_Live_bins/netcat.zip"
    print_file_info "strace.zip" "strace for all supported architectures" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/strace.zip" "external/EMBA_Live_bins/strace.zip"
    # Linux Kernel v4.14.336 - https://github.com/EMBA-support-repos/EMBA-v4.14.336
    print_file_info "Linux-Kernel-v4.14.336.zip" "Linux Kernel v4.14.336 for all supported architectures" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/Linux-Kernel-v4.14.336.zip" "external/EMBA_Live_bins/Linux-Kernel-v4.14.336.zip"


    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""The system emulation dependencies (if not already on the system) will be downloaded and installed!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

      mkdir -p external/EMBA_Live_bins

      apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

      # BusyBox - https://busybox.net/downloads/busybox-1.29.3.tar.bz2
      mkdir -p external/EMBA_Live_bins/busybox
      download_file "busybox.armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armel" "external/EMBA_Live_bins/busybox/busybox.armel"
      download_file "busybox.armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armelhf" "external/EMBA_Live_bins/busybox/busybox.armelhf"
      download_file "busybox.arm64el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.arm64el" "external/EMBA_Live_bins/busybox/busybox.arm64el"
      download_file "busybox.mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32eb" "external/EMBA_Live_bins/busybox/busybox.mips64n32eb"
      download_file "busybox.mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32el" "external/EMBA_Live_bins/busybox/busybox.mips64n32el"
      download_file "busybox.mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2eb" "external/EMBA_Live_bins/busybox/busybox.mips64r2eb"
      download_file "busybox.mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2el" "external/EMBA_Live_bins/busybox/busybox.mips64r2el"
      download_file "busybox.mips64v1eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64v1eb" "external/EMBA_Live_bins/busybox/busybox.mips64v1eb"
      download_file "busybox.mips64v1el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64v1el" "external/EMBA_Live_bins/busybox/busybox.mips64v1el"
      download_file "busybox.mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipseb" "external/EMBA_Live_bins/busybox/busybox.mipseb"
      download_file "busybox.mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipsel" "external/EMBA_Live_bins/busybox/busybox.mipsel"
      download_file "busybox.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.x86el" "external/EMBA_Live_bins/busybox/busybox.x86el"

      download_file "console.zip" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/console.zip" "external/EMBA_Live_bins/console.zip"
      download_file "libnvram.zip" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/libnvram.zip" "external/EMBA_Live_bins/libnvram.zip"
      download_file "strace.zip" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/strace.zip" "external/EMBA_Live_bins/strace.zip"
      download_file "gdb.zip" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/gdb.zip" "external/EMBA_Live_bins/gdb.zip"
      download_file "netcat.zip" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/netcat.zip" "external/EMBA_Live_bins/netcat.zip"
      download_file "Linux-Kernel-v4.14.336.zip" "https://github.com/EMBA-support-repos/EMBA-v4.14.336/releases/download/v4.14.336-initial/Linux-Kernel-v4.14.336.zip" "external/EMBA_Live_bins/Linux-Kernel-v4.14.336.zip"
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/console.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/libnvram.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/strace.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/gdb.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/Linux-Kernel-v4.14.336.zip

      rm external/EMBA_Live_bins/*.zip

      ;;
    esac
  fi
}


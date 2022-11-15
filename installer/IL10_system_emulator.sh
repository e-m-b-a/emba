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

IL10_system_emulator() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "$HOME_PATH" || ( echo "Could not install EMBA component system emulator" && exit 1 )

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

    # BusyBox - https://busybox.net/downloads/busybox-1.29.3.tar.bz2
    print_file_info "busybox.armel" "busybox ARMel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armel" "external/EMBA_Live_bins/busybox.armel"
    print_file_info "busybox.armelhf" "busybox ARMel hard float" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armelhf" "external/EMBA_Live_bins/busybox.armelhf"
    print_file_info "busybox.mips64n32eb" "busybox mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32eb" "external/EMBA_Live_bins/busybox.mips64n32eb"
    print_file_info "busybox.mips64n32el" "busybox mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32el" "external/EMBA_Live_bins/busybox.mips64n32el"
    print_file_info "busybox.mips64r2eb" "busybox mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2eb" "external/EMBA_Live_bins/busybox.mips64r2eb"
    print_file_info "busybox.mips64r2el" "busybox mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2el" "external/EMBA_Live_bins/busybox.mips64r2el"
    print_file_info "busybox.mipseb" "busybox mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipseb" "external/EMBA_Live_bins/busybox.mipseb"
    print_file_info "busybox.mipsel" "busybox mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipsel" "external/EMBA_Live_bins/busybox.mipsel"
    print_file_info "busybox.x86el" "busybox x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.x86el" "external/EMBA_Live_bins/busybox.x86el"

    # Console - https://github.com/EMBA-support-repos/firmadyne-console
    print_file_info "console.armel" "console ARMel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.armel" "external/EMBA_Live_bins/console.armel"
    print_file_info "console.armelhf" "console ARMel hard float" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.armelhf" "external/EMBA_Live_bins/console.armelhf"
    print_file_info "console.mips64n32eb" "console mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64n32eb" "external/EMBA_Live_bins/console.mips64n32eb"
    print_file_info "console.mips64n32el" "console mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64n32el" "external/EMBA_Live_bins/console.mips64n32el"
    print_file_info "console.mips64r2eb" "console mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64r2eb" "external/EMBA_Live_bins/console.mips64r2eb"
    print_file_info "console.mips64r2el" "console mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64r2el" "external/EMBA_Live_bins/console.mips64r2el"
    print_file_info "console.mipseb" "console mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mipseb" "external/EMBA_Live_bins/console.mipseb"
    print_file_info "console.mipsel" "console mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mipsel" "external/EMBA_Live_bins/console.mipsel"
    print_file_info "console.x86el" "console x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.x86el" "external/EMBA_Live_bins/console.x86el"

    # libnvram - https://github.com/EMBA-support-repos/FirmAE-libnvram
    print_file_info "libnvram.so.armel" "libnvram.so ARMel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.armel" "external/EMBA_Live_bins/libnvram.so.armel"
    print_file_info "libnvram.so.armelhf" "libnvram.so ARMel hard float" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.armelhf" "external/EMBA_Live_bins/libnvram.so.armelhf"
    print_file_info "libnvram.so.mips64n32eb" "libnvram.so mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64n32eb" "external/EMBA_Live_bins/libnvram.so.mips64n32eb"
    print_file_info "libnvram.so.mips64n32el" "libnvram.so mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64n32el" "external/EMBA_Live_bins/libnvram.so.mips64n32el"
    print_file_info "libnvram.so.mips64r2eb" "libnvram.so mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64r2eb" "external/EMBA_Live_bins/libnvram.so.mips64r2eb"
    print_file_info "libnvram.so.mips64r2el" "libnvram.so mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64r2el" "external/EMBA_Live_bins/libnvram.so.mips64r2el"
    print_file_info "libnvram.so.mipseb" "libnvram.so mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mipseb" "external/EMBA_Live_bins/libnvram.so.mipseb"
    print_file_info "libnvram.so.mipsel" "libnvram.so mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mipsel" "external/EMBA_Live_bins/libnvram.so.mipsel"
    print_file_info "libnvram.so.x86el" "libnvram.so x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.x86el" "external/EMBA_Live_bins/libnvram.so.x86el"

    # libnvram_ioctl - https://github.com/EMBA-support-repos/FirmAE-libnvram
    print_file_info "libnvram_ioctl.so.armel" "libnvram_ioctl.so ARMel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.armel" "external/EMBA_Live_bins/libnvram_ioctl.so.armel"
    print_file_info "libnvram_ioctl.so.armelhf" "libnvram_ioctl.so ARMel hard float" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.armelhf" "external/EMBA_Live_bins/libnvram_ioctl.so.armelhf"
    print_file_info "libnvram_ioctl.so.mips64n32eb" "libnvram_ioctl.so mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64n32eb" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64n32eb"
    print_file_info "libnvram_ioctl.so.mips64n32el" "libnvram_ioctl.so mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64n32el" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64n32el"
    print_file_info "libnvram_ioctl.so.mips64r2eb" "libnvram_ioctl.so mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64r2eb" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64r2eb"
    print_file_info "libnvram_ioctl.so.mips64r2el" "libnvram_ioctl.so mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64r2el" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64r2el"
    print_file_info "libnvram_ioctl.so.mipseb" "libnvram_ioctl.so mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mipseb" "external/EMBA_Live_bins/libnvram_ioctl.so.mipseb"
    print_file_info "libnvram_ioctl.so.mipsel" "libnvram_ioctl.so mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mipsel" "external/EMBA_Live_bins/libnvram_ioctl.so.mipsel"
    print_file_info "libnvram_ioctl.so.x86el" "libnvram_ioctl.so x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.x86el" "external/EMBA_Live_bins/libnvram_ioctl.so.x86el"

    # strace - https://github.com/EMBA-support-repos/strace
    print_file_info "strace.armel" "strace ARMel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.armel" "external/EMBA_Live_bins/strace.armel"
    print_file_info "strace.armelhf" "strace ARMel hard float" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.armelhf" "external/EMBA_Live_bins/strace.armelhf"
    # print_file_info "strace.mips64n32eb" "strace mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64n32eb" "external/EMBA_Live_bins/strace.mips64n32eb"
    # print_file_info "strace.mips64n32el" "strace mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64n32el" "external/EMBA_Live_bins/strace.mips64n32el"
    print_file_info "strace.mips64r2eb" "strace mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64r2eb" "external/EMBA_Live_bins/strace.mips64r2eb"
    print_file_info "strace.mips64r2el" "strace mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64r2el" "external/EMBA_Live_bins/strace.mips64r2el"
    print_file_info "strace.mipseb" "strace mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mipseb" "external/EMBA_Live_bins/strace.mipseb"
    print_file_info "strace.mipsel" "strace mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mipsel" "external/EMBA_Live_bins/strace.mipsel"
    print_file_info "strace.x86el" "strace x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.x86el" "external/EMBA_Live_bins/strace.x86el"

    # Linux Kernel 4.1.17 - https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1
    print_file_info "zImage.armel" "zImage armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/zImage.armel" "external/EMBA_Live_bins/zImage.armel"
    print_file_info "zImage.armelhf" "zImage armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/zImage.armelhf" "external/EMBA_Live_bins/zImage.armelhf"print_file_info "vmlinux.mips64n32eb" "vmlinux mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mips64n32eb.4" "external/EMBA_Live_bins/vmlinux.mips64n32eb.4"
    print_file_info "vmlinux.mips64r2eb" "vmlinux mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mips64r2eb.4" "external/EMBA_Live_bins/vmlinux.mips64r2eb.4"
    print_file_info "vmlinux.mips64r2el" "vmlinux mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mips64r2el.4" "external/EMBA_Live_bins/vmlinux.mips64r2el.4"
    print_file_info "vmlinux.mipseb" "vmlinux mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mipseb.4" "external/EMBA_Live_bins/vmlinux.mipseb.4"
    print_file_info "vmlinux.mipsel" "vmlinux mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mipsel.4" "external/EMBA_Live_bins/vmlinux.mipsel.4"
    print_file_info "vmlinux.x86el" "vmlinux x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.x86el" "external/EMBA_Live_bins/vmlinux.x86el"
    print_file_info "bzImage.x86el" "bzImage x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/bzImage.x86el" "external/EMBA_Live_bins/bzImage.x86el"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The system emulation dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

      mkdir -p external/EMBA_Live_bins

      # to ensure old EMBA versions do not completeley break - remove this at the beginning of 2023
      mkdir -p external/firmae/
      ln -s external/EMBA_Live_bins external/firmae/binaries
      # END - remove this at the beginning of 2023

      apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

      # BusyBox - https://busybox.net/downloads/busybox-1.29.3.tar.bz2
      download_file "busybox.armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armel" "external/EMBA_Live_bins/busybox.armel"
      download_file "busybox.armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.armelhf" "external/EMBA_Live_bins/busybox.armelhf"
      download_file "busybox.mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32eb" "external/EMBA_Live_bins/busybox.mips64n32eb"
      download_file "busybox.mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64n32el" "external/EMBA_Live_bins/busybox.mips64n32el"
      download_file "busybox.mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2eb" "external/EMBA_Live_bins/busybox.mips64r2eb"
      download_file "busybox.mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mips64r2el" "external/EMBA_Live_bins/busybox.mips64r2el"
      download_file "busybox.mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipseb" "external/EMBA_Live_bins/busybox.mipseb"
      download_file "busybox.mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.mipsel" "external/EMBA_Live_bins/busybox.mipsel"
      download_file "busybox.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/busybox.x86el" "external/EMBA_Live_bins/busybox.x86el"

      # Console - https://github.com/EMBA-support-repos/firmadyne-console
      download_file "console.armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.armel" "external/EMBA_Live_bins/console.armel"
      download_file "console.armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.armelhf" "external/EMBA_Live_bins/console.armelhf"
      download_file "console.mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64n32eb" "external/EMBA_Live_bins/console.mips64n32eb"
      download_file "console.mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64n32el" "external/EMBA_Live_bins/console.mips64n32el"
      download_file "console.mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64r2eb" "external/EMBA_Live_bins/console.mips64r2eb"
      download_file "console.mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mips64r2el" "external/EMBA_Live_bins/console.mips64r2el"
      download_file "console.mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mipseb" "external/EMBA_Live_bins/console.mipseb"
      download_file "console.mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.mipsel" "external/EMBA_Live_bins/console.mipsel"
      download_file "console.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/console.x86el" "external/EMBA_Live_bins/console.x86el"

      # libnvram - https://github.com/EMBA-support-repos/FirmAE-libnvram
      download_file "libnvram.so.armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.armel" "external/EMBA_Live_bins/libnvram.so.armel"
      download_file "libnvram.so.armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.armelhf" "external/EMBA_Live_bins/libnvram.so.armelhf"
      download_file "libnvram.so.mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64n32eb" "external/EMBA_Live_bins/libnvram.so.mips64n32eb"
      download_file "libnvram.so.mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64n32el" "external/EMBA_Live_bins/libnvram.so.mips64n32el"
      download_file "libnvram.so.mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64r2eb" "external/EMBA_Live_bins/libnvram.so.mips64r2eb"
      download_file "libnvram.so.mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mips64r2el" "external/EMBA_Live_bins/libnvram.so.mips64r2el"
      download_file "libnvram.so.mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mipseb" "external/EMBA_Live_bins/libnvram.so.mipseb"
      download_file "libnvram.so.mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.mipsel" "external/EMBA_Live_bins/libnvram.so.mipsel"
      download_file "libnvram.so.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram.so.x86el" "external/EMBA_Live_bins/libnvram.so.x86el"

      # libnvram_ioctl - https://github.com/EMBA-support-repos/FirmAE-libnvram
      download_file "libnvram_ioctl.so.armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.armel" "external/EMBA_Live_bins/libnvram_ioctl.so.armel"
      download_file "libnvram_ioctl.so.armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.armelhf" "external/EMBA_Live_bins/libnvram_ioctl.so.armelhf"
      download_file "libnvram_ioctl.so.mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64n32eb" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64n32eb"
      download_file "libnvram_ioctl.so.mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64n32el" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64n32el"
      download_file "libnvram_ioctl.so.mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64r2eb" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64r2eb"
      download_file "libnvram_ioctl.so.mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mips64r2el" "external/EMBA_Live_bins/libnvram_ioctl.so.mips64r2el"
      download_file "libnvram_ioctl.so.mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mipseb" "external/EMBA_Live_bins/libnvram_ioctl.so.mipseb"
      download_file "libnvram_ioctl.so.mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.mipsel" "external/EMBA_Live_bins/libnvram_ioctl.so.mipsel"
      download_file "libnvram_ioctl.so.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/libnvram_ioctl.so.x86el" "external/EMBA_Live_bins/libnvram_ioctl.so.x86el"

      # strace - https://github.com/EMBA-support-repos/strace
      download_file "strace.armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.armel" "external/EMBA_Live_bins/strace.armel"
      download_file "strace.armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.armelhf" "external/EMBA_Live_bins/strace.armelhf"
      # download_file "strace.mips64n32eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64n32eb" "external/EMBA_Live_bins/strace.mips64n32eb"
      # download_file "strace.mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64n32el" "external/EMBA_Live_bins/strace.mips64n32el"
      download_file "strace.mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64r2eb" "external/EMBA_Live_bins/strace.mips64r2eb"
      download_file "strace.mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mips64r2el" "external/EMBA_Live_bins/strace.mips64r2el"
      download_file "strace.mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mipseb" "external/EMBA_Live_bins/strace.mipseb"
      download_file "strace.mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.mipsel" "external/EMBA_Live_bins/strace.mipsel"
      download_file "strace.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/strace.x86el" "external/EMBA_Live_bins/strace.x86el"

      # Linux Kernel 4.1.17 - https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1
      download_file "zImage.armel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/zImage.armel" "external/EMBA_Live_bins/zImage.armel"
      download_file "zImage.armelhf" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/zImage.armelhf" "external/EMBA_Live_bins/zImage.armelhf"
      download_file "vmlinux.mips64n32eb" "vmlinux mips64n32el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mips64n32eb.4" "external/EMBA_Live_bins/vmlinux.mips64n32eb.4"
      download_file "vmlinux.mips64r2eb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mips64r2eb.4" "external/EMBA_Live_bins/vmlinux.mips64r2eb.4"
      download_file "vmlinux.mips64r2el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mips64r2el.4" "external/EMBA_Live_bins/vmlinux.mips64r2el.4"
      download_file "vmlinux.mipseb" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mipseb.4" "external/EMBA_Live_bins/vmlinux.mipseb.4"
      download_file "vmlinux.mipsel" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.mipsel.4" "external/EMBA_Live_bins/vmlinux.mipsel.4"
      download_file "vmlinux.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/vmlinux.x86el" "external/EMBA_Live_bins/vmlinux.x86el"
      download_file "bzImage.x86el" "https://github.com/EMBA-support-repos/FirmAE_kernel-v4.1/releases/download/all-new-binaries/bzImage.x86el" "external/EMBA_Live_bins/bzImage.x86el"
      ;;
    esac
  fi
}


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

# Description:  Installs full system emulation dependencies
#               Module is based on FirmAE and firmadyne

IL10_system_emulator() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "${HOME_PATH}" || ( echo "Could not install EMBA component system emulator" && exit 1 )

    UML_UTILITIES_URL="http://ftp.de.debian.org/debian/pool/main/u/uml-utilities/uml-utilities_20070815.4-2.1_amd64.deb"

    print_tool_info "busybox-static" 1
    print_tool_info "bash-static" 1
    print_tool_info "fakeroot" 1
    print_tool_info "git" 1
    print_tool_info "dmsetup" 1
    print_tool_info "kpartx" 1
    # uml-utilities provides tunctl for L10 -> uml-utilities was removed somewhere in August 2024
    # print_tool_info "uml-utilities" 1
    print_tool_info "libfuse2t64" 1
    print_file_info "uml-utilities.deb" "uml-utilities" "${UML_UTILITIES_URL}" "external/uml-utilities.deb"
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
    # EMBAbite
    print_tool_info "netcat-openbsd" 1
    print_tool_info "tnftp" 1

    # Busybox version (1.29.3 / 1.36.1)
    BB_VER="1.36.1"
    GDB_VER="8.3.1"

    print_file_info "busybox.zip" "Busybox" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/busybox-v${BB_VER}.zip" "external/EMBA_Live_bins/busybox.zip"
    print_file_info "console.zip" "console for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/console.zip" "external/EMBA_Live_bins/console.zip"
    print_file_info "gdb.zip" "GDB and gdbserver for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/gdb-${GDB_VER}.zip" "external/EMBA_Live_bins/gdb.zip"
    print_file_info "gdbserver.zip" "GDB and gdbserver for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/gdbserver-${GDB_VER}.zip" "external/EMBA_Live_bins/gdbserver.zip"
    print_file_info "libnvram.zip" "libnvram for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/libnvram.zip" "external/EMBA_Live_bins/libnvram.zip"
    print_file_info "libnvram_ioctl.zip" "libnvram for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/libnvram_ioctl.zip" "external/EMBA_Live_bins/libnvram_ioctl.zip"
    print_file_info "netcat.zip" "netcat for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/netcat.zip" "external/EMBA_Live_bins/netcat.zip"
    print_file_info "strace.zip" "strace for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/strace.zip" "external/EMBA_Live_bins/strace.zip"
    print_file_info "Linux-Kernel-v4.14.336.zip" "Linux Kernel v4.14.336 for all supported architectures" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/Linux-Kernel-v4.14.336.zip" "external/EMBA_Live_bins/Linux-Kernel-v4.14.336.zip"

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

      download_file "uml-utilities.deb" "${UML_UTILITIES_URL}" "external/uml-utilities.deb"
      dpkg -i "external/uml-utilities.deb"
      rm -f "external/uml-utilities.deb"

      download_file "busybox.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/busybox-v${BB_VER}.zip" "external/EMBA_Live_bins/busybox.zip"
      download_file "console.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/console.zip" "external/EMBA_Live_bins/console.zip"
      download_file "gdb.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/gdb-${GDB_VER}.zip" "external/EMBA_Live_bins/gdb.zip"
      download_file "gdbserver.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/gdbserver-${GDB_VER}.zip" "external/EMBA_Live_bins/gdbserver.zip"
      download_file "libnvram.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/libnvram.zip" "external/EMBA_Live_bins/libnvram.zip"
      download_file "libnvram_ioctl.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/libnvram_ioctl.zip" "external/EMBA_Live_bins/libnvram_ioctl.zip"
      download_file "netcat.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/netcat.zip" "external/EMBA_Live_bins/netcat.zip"
      download_file "strace.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/strace.zip" "external/EMBA_Live_bins/strace.zip"
      download_file "Linux-Kernel-v4.14.336.zip" "https://github.com/EMBA-support-repos/EMBA_emulation_kernel-v4.1.52/releases/download/4.1.52-init/Linux-Kernel-v4.14.336.zip" "external/EMBA_Live_bins/Linux-Kernel-v4.14.336.zip"

      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/busybox.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/console.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/gdb.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/gdbserver.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/libnvram.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/libnvram_ioctl.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/netcat.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/strace.zip
      unzip -d external/EMBA_Live_bins/ external/EMBA_Live_bins/Linux-Kernel-v4.14.336.zip

      rm external/EMBA_Live_bins/*.zip

      ;;
    esac
  fi
}


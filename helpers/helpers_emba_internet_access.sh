#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description: Multiple useful helpers used to access online resources

kernel_downloader() {
  LOG_FILE_KERNEL="$CSV_DIR"/s24_kernel_bin_identifier.csv
  KERNEL_ARCH_PATH="$EXT_DIR"/linux_kernel_sources/

  if ! [[ -d "$KERNEL_ARCH_PATH" ]]; then
    mkdir "$KERNEL_ARCH_PATH"
  fi

  # we wait until the s24 module is finished and hopefully shows us a kernel version
  while ! [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; do
    sleep 1
  done
  if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
    while [[ $(grep -c S24_kernel_bin_identifier "$LOG_DIR"/"$MAIN_LOG_FILE") -lt 2 ]]; do
      sleep 1
    done
  fi
  # now we should have a csv log with a kernel version:
  if ! [[ -f "$LOG_FILE_KERNEL" ]]; then
    print_output "[-] No Kernel version identified ..." "no_log"
    return
  fi
  local K_VERSIONS=()
  local K_VERSION=""

  mapfile -t K_VERSIONS < <(cut -d\; -f2 "$LOG_FILE_KERNEL" | tail -n +2 | sort -u | grep -E "[0-9]+(\.[0-9]+)+?" || true)

  for K_VERSION in "${K_VERSIONS[@]}"; do
    print_output "[*] Checking download of kernel version $ORANGE$K_VERSION$NC" "no_log"
    local K_VER_DOWNLOAD=""
    local K_VER_1st=""
    local K_VER_2nd=""
    local K_VER_3rd=""
  
    K_VER_1st=$(echo "$K_VERSION" | cut -d. -f1)
    K_VER_2nd=$(echo "$K_VERSION" | cut -d. -f2)
    K_VER_3rd=$(echo "$K_VERSION" | cut -d. -f3)
    if [[ "$K_VER_1st" -lt 3 ]]; then
      K_VER_DOWNLOAD="$K_VER_1st"".""$K_VER_2nd"
    elif [[ "$K_VER_1st" -eq 3 && "$K_VER_2nd" -eq 0 ]]; then
      K_VER_DOWNLOAD="$K_VER_1st"".""$K_VER_2nd"
    else
      K_VER_DOWNLOAD="$K_VER_1st"".x"
    fi
    if [[ "$K_VER_3rd" -eq 0 ]]; then
      # for download we need to modify versions like 3.1.0 to 3.1
      K_VERSION="$K_VER_1st"".""$K_VER_2nd"
    fi
  
    if ! [[ -f "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz ]]; then
      print_output "[*] Kernel download for version $ORANGE$K_VERSION$NC" "no_log"
      wget https://mirrors.edge.kernel.org/pub/linux/kernel/v"$K_VER_DOWNLOAD"/linux-"$K_VERSION".tar.gz -O "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz || true
    fi
  
    if ! [[ -f "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz ]]; then
      print_output "[-] Kernel sources not available ..." "no_log"
      continue
    fi
    if ! file "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz | grep -q "gzip compressed data"; then
      print_output "[-] Kernel sources not available ..." "no_log"
      continue
    fi
    print_output "[*] Kernel source for version $ORANGE$K_VERSION$NC stored in $ORANGE$KERNEL_ARCH_PATH$NC" "no_log"
  done
}


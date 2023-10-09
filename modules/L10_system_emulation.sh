#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
# Original copyright of firmae and firmadyne:
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2015 - 2016, Daming Dominic Chen
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# The code of the original projects is licensed under the MIT license - all changes are released under GPLv3
# see also /licenses/
#
# Author(s): Michael Messner

# Description:  Builds and emulates Linux firmware - this module is based on the great work of firmadyne and firmAE
#               Check out the original firmadyne project at https://github.com/firmadyne
#               Check out the original FirmAE project at https://github.com/pr0v3rbs/FirmAE
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
# Warning:      This module changes your network configuration and it could happen that your system looses
#               network connectivity.

L10_system_emulation() {
  module_log_init "${FUNCNAME[0]}"
  module_title "System emulation of Linux based embedded devices."

  # enable DEBUG_MODE for further debugging capabilities:
  # * create_emulation_archive for all attempts
  # * do not stop after 2 deteted network services
  export DEBUG_MODE=0

  export SYS_ONLINE=0
  export TCP=""
  local MODULE_END=0
  local UNSUPPORTED_ARCH=0
  export STATE_CHECK_MECHANISM="PING"

  if [[ "${FULL_EMULATION}" -eq 1 && "${RTOS}" -eq 0 ]]; then
    pre_module_reporter "${FUNCNAME[0]}"
    export MODULE_SUB_PATH="${MOD_DIR}"/"${FUNCNAME[0]}"
    S25_LOG="s25_kernel_check.txt"

    if [[ "${ARCH}" == "MIPS"* || "${ARCH}" == "ARM"* || "${ARCH}" == "x86" ]]; then

      # WARNING: false was never tested ;)
      # Could be interesting for future extensions
      set_firmae_arbitration "true"

      export BINARY_DIR="${EXT_DIR}/EMBA_Live_bins"
      FIRMWARE_PATH_orig="$(abs_path "${FIRMWARE_PATH_BAK}")"
      LOG_PATH_MODULE=$(abs_path "${LOG_PATH_MODULE}")
      R_PATH_CNT=1

      # handling restarted scans with old emulation processes:
      if [[ -f "${LOG_DIR}"/emulator_online_results.log ]] && grep -q "L10_system_emulation finished" "${LOG_DIR}"/emba.log; then
        print_ln
        print_output "[*] Found finished emulation process - trying to recover old emulation process"

        export IP_ADDRESS_=""
        local IMAGE_DIR=""
        export IMAGE_NAME=""
        export ARCHIVE_PATH=""
        export HOSTNETDEV_ARR=()
        local EMULATION_ENTRY=""

        EMULATION_ENTRY="$(grep "TCP ok" "${LOG_DIR}"/emulator_online_results.log | sort -k 7 -t ';' | tail -1)"
        IP_ADDRESS_=$(grep "TCP ok" "${LOG_DIR}"/emulator_online_results.log | sort -k 7 -t ';' | tail -1 | cut -d\; -f8 | awk '{print $3}')
        IMAGE_DIR="$(grep "TCP ok" "${LOG_DIR}"/emulator_online_results.log | sort -k 7 -t ';' | tail -1 | cut -d\; -f10)"
        ARCHIVE_PATH="${OLD_LOG_DIR}""/""${IMAGE_DIR}"

        print_output "[*] Recovered IP address: ${ORANGE}${IP_ADDRESS_}${NC}"
        print_output "[*] Recovered IMAGE_DIR: ${ORANGE}${IMAGE_DIR}${NC}"
        print_output "[*] Recovered ARCHIVE_PATH: ${ORANGE}${ARCHIVE_PATH}${NC}"

        if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
          IMAGE_NAME="$(tr ' ' '\n' < "${ARCHIVE_PATH}"/run.sh | grep -o "file=.*" | cut -d '/' -f2)"
          print_output "[*] Identified IMAGE_NAME: ${ORANGE}${IMAGE_NAME}${NC}" "no_log"
          print_output "[+] Startup script (run.sh) found in old logs ... restarting emulation process now"
          mapfile -t HOSTNETDEV_ARR < <(grep "ip link set.*up" "${ARCHIVE_PATH}"/run.sh | awk '{print $4}' | sort -u)

          if [[ "${EMULATION_ENTRY}" == *"ICMP not ok"* ]]; then
            print_output "[*] Testing system recovery with hping instead of ping" "no_log"
            STATE_CHECK_MECHANISM="HPING"
          fi
          # we should get TCP="ok" and SYS_ONLINE=1 back
          if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
            print_output "[-] System recovery went wrong. No further analysis possible" "no_log"
          fi
        else
          print_output "[-] No archive path found in old logs ... restarting emulation process not possible"
        fi
      fi

      if [[ "${SYS_ONLINE}" -ne 1 ]] && [[ "${TCP}" != "ok" ]]; then
        for R_PATH in "${ROOT_PATH[@]}" ; do
          print_output "[*] Testing root path (${ORANGE}${R_PATH_CNT}${NC}/${ORANGE}${#ROOT_PATH[@]}${NC}): ${ORANGE}${R_PATH}${NC}"
          if grep -q "P55_unblob_extractor nothing reported" "${LOG_DIR}"/p55_unblob_extractor.txt 2>/dev/null; then
            if ! grep -q "P60_deep_extractor nothing reported" "${LOG_DIR}"/p60_deep_extractor.txt 2>/dev/null; then
              [[ -f "${LOG_DIR}"/p60_deep_extractor.txt ]] && write_link "p60"
            fi
          else
            [[ -f "${LOG_DIR}"/p55_unblob_extractor.txt ]] && write_link "p55"
          fi

          if [[ -n "${D_END}" ]]; then
            TAPDEV_0="tap0_0"
            D_END="$(echo "${D_END}" | tr '[:upper:]' '[:lower:]')"
            ARCH_END="$(echo "${ARCH}" | tr '[:upper:]' '[:lower:]')$(echo "${D_END}" | tr '[:upper:]' '[:lower:]')"

            # default is ARM_SF -> we only need to check if it is HF
            # The information is based on the results of architecture_check()
            if [[ -n "${ARM_HF}" ]] && [[ "${ARM_HF}" -gt "${ARM_SF:-0}" ]]; then
              print_output "[*] ARM hardware floating detected"
              ARCH_END="${ARCH_END}""hf"
            fi

            if [[ "${ARCH_END}" == "armbe"* ]] || [[ "${ARCH_END}" == "mips64r2"* ]] || [[ "${ARCH_END}" == "mips64_3"* ]]; then
              print_output "[-] Found NOT supported architecture ${ORANGE}${ARCH_END}${NC}"
              [[ -f "${LOG_DIR}"/p99_prepare_analyzer.txt ]] && write_link "p99"
              print_output "[-] Please open a new issue here: https://github.com/e-m-b-a/emba/issues"
              UNSUPPORTED_ARCH=1
              return
            fi

            # just in case we remove the return in the unsupported arch checker for testing:
            if [[ "${UNSUPPORTED_ARCH}" -ne 1 ]]; then
              print_output "[*] Found supported architecture ${ORANGE}${ARCH_END}${NC}"
              write_link "p99"
            fi

            pre_cleanup_emulator

            main_emulation "${R_PATH}" "${ARCH_END}"

            if [[ -d "${MNT_POINT}" ]]; then
              rm -r "${MNT_POINT}" || true
            fi

            if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
              # do not test other root paths if we are already online (some ports are available)
              if [[ "${DEBUG_MODE}" -eq 1 ]]; then
                print_output "[!] Debug mode: We do not stop here ..."
              else
                break
              fi
            fi
          else
            print_output "[!] No supported architecture detected"
          fi
          ((R_PATH_CNT+=1))
        done
        print_system_emulation_results
      fi
      MODULE_END=1
    else
      print_output "[!] No supported architecture found.\\n"
      print_output "[!] Curently supported: ${ORANGE}ARM${NC}, ${ORANGE}MIPS${NC} and ${ORANGE}x86${NC}.\\n"
      MODULE_END=0
    fi
  fi

  if [[ -f "${LOG_DIR}"/emulator_online_results.log ]]; then
    if [[ $(grep -c "TCP ok" "${LOG_DIR}"/emulator_online_results.log || true) -gt 0 ]]; then
      print_ln
      print_output "[+] Identified the following system emulation results (with running network services):"
      export HOSTNETDEV_ARR=()
      local IMAGE_DIR=""
      local SYS_EMUL_POS_ENTRY=""
      SYS_EMUL_POS_ENTRY="$(grep "TCP ok" "${LOG_DIR}"/emulator_online_results.log | sort -t ';' -k7 -n -r | head -1 || true)"
      print_output "$(indent "$(orange "${SYS_EMUL_POS_ENTRY}")")"

      IP_ADDRESS_=$(echo "${SYS_EMUL_POS_ENTRY}" | grep "TCP ok" | sort -k 7 -t ';' | tail -1 | cut -d\; -f8 | awk '{print $3}')
      IMAGE_DIR="$(echo "${SYS_EMUL_POS_ENTRY}" | grep "TCP ok" | sort -k 7 -t ';' | tail -1 | cut -d\; -f10)"
      ARCHIVE_PATH="${LOG_PATH_MODULE}""/""${IMAGE_DIR}"
      print_ln
      print_output "[*] Identified IP address: ${ORANGE}${IP_ADDRESS_}${NC}" "no_log"
      print_output "[*] Identified IMAGE_DIR: ${ORANGE}${IMAGE_DIR}${NC}" "no_log"
      print_output "[*] Identified ARCHIVE_PATH: ${ORANGE}${ARCHIVE_PATH}${NC}" "no_log"

      if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
        IMAGE_NAME="$(tr ' ' '\n' < "${ARCHIVE_PATH}"/run.sh | grep -o "file=.*" | cut -d '/' -f2)"
        print_output "[*] Identified IMAGE_NAME: ${ORANGE}${IMAGE_NAME}${NC}" "no_log"
        print_output "[+] Identified emulation startup script (run.sh) in ARCHIVE_PATH ... starting emulation process for further analysis" "no_log"
        print_ln
        mapfile -t HOSTNETDEV_ARR < <(grep "ip link set.*up" "${ARCHIVE_PATH}"/run.sh | awk '{print $4}' | sort -u)
        if [[ "${SYS_EMUL_POS_ENTRY}" == *"ICMP not ok"* ]]; then
          print_output "[*] Testing system recovery with hping instead of ping" "no_log"
          STATE_CHECK_MECHANISM="HPING"
        fi
        # we should get TCP="ok" and SYS_ONLINE=1 back
        if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System recovery went wrong. No further analysis possible" "no_log"
        fi
      else
        print_output "[-] ${ORANGE}WARNING:${NC} No archive path found in logs ... restarting emulation process for further analysis not possible" "no_log"
      fi
    fi
   fi

  module_end_log "${FUNCNAME[0]}" "${MODULE_END}"
}

print_system_emulation_results() {
  if [[ -f "${LOG_DIR}"/emulator_online_results.log ]]; then
    sub_module_title "System emulation results"
    print_output "EMBA was able to identify the following system emulation results:"
    print_ln

    local EMU_RES=""

    while read -r EMU_RES; do
      EMU_RES=$(echo "${EMU_RES}" | cut -d\; -f2-) 
      if [[ "${EMU_RES}" == *"ICMP ok"* ]] || [[ "${EMU_RES}" == *"TCP-0 ok"* ]] || [[ "${EMU_RES}" == *"TCP ok"* ]]; then
        print_output "[+] ${EMU_RES}"
      else
        print_output "[*] ${EMU_RES}"
      fi
    done < "${LOG_DIR}"/emulator_online_results.log
  fi
}

pre_cleanup_emulator() {
  # this cleanup function is to ensure that we have no mounts from previous tests mounted
  print_output "[*] Checking for not unmounted proc, sys and run in log directory"
  mapfile -t CHECK_MOUNTS < <(mount | grep "${LOG_DIR}" | grep "proc\|sys\|run" || true)
  for MOUNT in "${CHECK_MOUNTS[@]}"; do
    print_output "[*] Unmounting ${MOUNT}"
    MOUNT=$(echo "${MOUNT}" | cut -d\  -f3)
    umount -l "${MOUNT}" || true
  done
}

cleanup_tap() {
  mapfile -t TAP_CLEAN < <(ifconfig | grep tap | cut -d: -f1 || true)
  for TAP_TO_CLEAN in "${TAP_CLEAN[@]}"; do
    print_output "[*] Cleaning up TAP interface ${TAP_TO_CLEAN}"
    tunctl -d "${TAP_TO_CLEAN}" || true
  done
}

create_emulation_filesystem() {
  # based on the original firmAE script:
  # https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/makeImage.sh

  sub_module_title "Create Qemu filesystem for full system emulation"
  ROOT_PATH="${1:-}"
  ARCH_END="${2:-}"
  local BINARY_L10=""
  local BINARIES_L10=()

  export IMAGE_NAME
  IMAGE_NAME="$(basename "${ROOT_PATH}")_${ARCH_END}-${RANDOM}"

  MNT_POINT="${LOG_PATH_MODULE}/emulation_tmp_fs_firmae"
  if [[ -d "${MNT_POINT}" ]]; then
    MNT_POINT="${MNT_POINT}"-"${RANDOM}"
  fi
  mkdir "${MNT_POINT}" || true

  print_output "[*] Create Qemu filesystem for emulation - ${ROOT_PATH}.\\n"
  IMAGE_SIZE="$(du -b --max-depth=0 "${ROOT_PATH}" | awk '{print $1}')"
  IMAGE_SIZE=$((IMAGE_SIZE + 400 * 1024 * 1024))

  print_output "[*] Size of filesystem for emulation - ${ORANGE}${IMAGE_SIZE}${NC}.\\n"
  print_output "[*] Name of filesystem for emulation - ${ORANGE}${IMAGE_NAME}${NC}.\\n"
  qemu-img create -f raw "${LOG_PATH_MODULE}/${IMAGE_NAME}" "${IMAGE_SIZE}"
  chmod a+rw "${LOG_PATH_MODULE}/${IMAGE_NAME}"

  print_output "[*] Creating Partition Table"
  echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "${LOG_PATH_MODULE}/${IMAGE_NAME}"

  print_output "[*] Identify Qemu Image device for ${ORANGE}${LOG_PATH_MODULE}/${IMAGE_NAME}${NC}"
  DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
  if [[ "${DEVICE}" == "NA" ]]; then
    DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
  fi
  if [[ "${DEVICE}" == "NA" ]]; then
    print_output "[-] No Qemu Image device identified"
    return
  fi
  print_output "[*] Qemu Image device: ${ORANGE}${DEVICE}${NC}"
  sleep 1
  print_output "[*] Device mapper created at ${ORANGE}${DEVICE}${NC}"

  print_output "[*] Creating Filesystem"
  sync
  mkfs.ext2 "${DEVICE}"

  print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
  mount "${DEVICE}" "${MNT_POINT}" || true

  if mount | grep -q "${MNT_POINT}"; then

    print_output "[*] Copy extracted root filesystem to new QEMU image"
    cp -prf "${ROOT_PATH}"/* "${MNT_POINT}"/ || (print_output "[-] Warning: Root filesystem not copied!" && return)

    if [[ -f "${HELP_DIR}"/fix_bins_lnk_emulation.sh ]] && [[ $(find "${MNT_POINT}" -type l | wc -l) -lt 10 ]]; then
      print_output "[*] No symlinks found in firmware ... Starting link fixing helper ..."
      "${HELP_DIR}"/fix_bins_lnk_emulation.sh "${MNT_POINT}"
    else
      # ensure that the needed permissions for exec files are set correctly
      # This is needed at some firmwares have corrupted permissions on ELF or sh files
      print_output "[*] Multiple firmwares have broken script and ELF permissions - We fix them now"
      readarray -t BINARIES_L10 < <( find "${MNT_POINT}" -xdev -type f -exec file {} \; 2>/dev/null | grep "ELF\|executable" | cut -d: -f1)
      for BINARY_L10 in "${BINARIES_L10[@]}"; do
        [[ -x "${BINARY_L10}" ]] && continue
        if [[ -f "${BINARY_L10}" ]]; then
          chmod +x "${BINARY_L10}"
        fi
      done
    fi

    print_output "[*] Creating FIRMADYNE directories within the firmware environment"
    mkdir -p "${MNT_POINT}/firmadyne/libnvram/" || true
    mkdir -p "${MNT_POINT}/firmadyne/libnvram.override/" || true

    print_output "[*] Patching filesystem (chroot)"
    cp "$(command -v busybox)" "${MNT_POINT}" || true
    cp "$(command -v bash-static)" "${MNT_POINT}" || true

    if [[ -f "${CSV_DIR}"/s24_kernel_bin_identifier.csv ]]; then
      # kernelInit is getting the output of the init command line we get from s24
      if grep -q "init=" "${CSV_DIR}"/s24_kernel_bin_identifier.csv; then
        print_output "[*] Found init entry for kernel - see ${ORANGE}${LOG_DIR}/s24_kernel_bin_identifier.txt${NC}:"
        grep "init=/" "${CSV_DIR}"/s24_kernel_bin_identifier.csv | cut -d\; -f5 | sed -e 's/.*init=/init=/' | awk '{print $1}'| sort -u | tee -a "${MNT_POINT}"/kernelInit
        tee -a "${LOG_FILE}" < "${MNT_POINT}"/kernelInit
      fi
    else
      print_output "[-] No results from S24 kernel module found"
    fi

    print_output "[*] fixImage.sh (chroot)"
    cp "${MODULE_SUB_PATH}/fixImage.sh" "${MNT_POINT}" || true
    FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /busybox ash /fixImage.sh | tee -a "${LOG_FILE}"

    print_output "[*] inferFile.sh (chroot)"
    # -> this re-creates init file and builds up the service which is ued from run_service.sh
    cp "${MODULE_SUB_PATH}/inferFile.sh" "${MNT_POINT}" || true
    FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /bash-static /inferFile.sh | tee -a "${LOG_FILE}"

    print_output "[*] inferService.sh (chroot)"
    cp "${MODULE_SUB_PATH}/inferService.sh" "${MNT_POINT}" || true
    FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /bash-static /inferService.sh | tee -a "${LOG_FILE}"

    if [[ -f "${MODULE_SUB_PATH}/injection_check.sh" ]]; then
      # injection checker - future extension
      INJECTION_MARKER="${RANDOM}"
      if [[ -d "${MNT_POINT}"/bin ]]; then
        cp "${MODULE_SUB_PATH}/injection_check.sh" "${MNT_POINT}"/bin/a || true
        chmod a+x "${MNT_POINT}/bin/a" || true
        sed -i 's/asdfqwertz/'"d34d_${INJECTION_MARKER}"'/' "${MNT_POINT}"/bin/a || true
      fi
      if [[ -d "${MNT_POINT}"/sbin ]]; then
        cp "${MODULE_SUB_PATH}/injection_check.sh" "${MNT_POINT}"/sbin/a || true
        chmod a+x "${MNT_POINT}/sbin/a" || true
        sed -i 's/asdfqwertz/'"d34d_${INJECTION_MARKER}"'/' "${MNT_POINT}"/sbin/a || true
      fi
      if [[ -f "${MNT_POINT}/sbin/a" ]] || [[ -f "${MNT_POINT}/bin/a" ]]; then
        print_output "[*] Generated injection scripts with marker ${ORANGE}${INJECTION_MARKER}${NC}."
        cat "${MNT_POINT}"/bin/a
      fi

      # setup a marker for traversal tests
      echo "EMBA_${INJECTION_MARKER}_EMBA" > "${MNT_POINT}"/dir_trav_check
      echo "${INJECTION_MARKER}" > "${LOG_PATH_MODULE}"/injection_marker.log
    fi

    if [[ -e "${MNT_POINT}/kernelInit" ]]; then
      print_output "[*] Backup ${MNT_POINT}/kernelInit:"
      tee -a "${LOG_FILE}" < "${MNT_POINT}/kernelInit"
      rm "${MNT_POINT}/kernelInit"
    fi

    rm "${MNT_POINT}/fixImage.sh" || true
    rm "${MNT_POINT}/inferFile.sh" || true
    rm "${MNT_POINT}/busybox" || true
    rm "${MNT_POINT}/bash-static" || true

    print_output "[*] Setting up system mode emulation environment on target filesystem"
    # FirmAE binaries (we only use a subset of them):
    BINARIES=( "busybox" "console" "libnvram.so" "libnvram_ioctl.so" "strace" "gdb" "gdbserver" )
    for BINARY_NAME in "${BINARIES[@]}"; do
      BINARY_PATH=$(get_binary "${BINARY_NAME}" "${ARCH_END}")
      if ! [[ -f "${BINARY_PATH}" ]]; then
        print_output "[-] Missing ${ORANGE}${BINARY_PATH}${NC} - no setup possible"
        continue
      fi
      print_output "[*] Setting up ${ORANGE}${BINARY_NAME}${NC} - ${ORANGE}${ARCH_END}${NC} (${ORANGE}${BINARY_PATH}${NC})"
      cp "${BINARY_PATH}" "${MNT_POINT}/firmadyne/${BINARY_NAME}"
      chmod a+x "${MNT_POINT}/firmadyne/${BINARY_NAME}"
    done

    mknod -m 666 "${MNT_POINT}/firmadyne/ttyS1" c 4 65

    print_output "[*] Setting up emulation scripts"
    cp "${MODULE_SUB_PATH}/preInit.sh" "${MNT_POINT}/firmadyne/preInit.sh" || true
    chmod a+x "${MNT_POINT}/firmadyne/preInit.sh"

    # network.sh
    cp "${MODULE_SUB_PATH}/network.sh" "${MNT_POINT}/firmadyne/network.sh" || true
    chmod a+x "${MNT_POINT}/firmadyne/network.sh"

    # run_service.sh
    cp "${MODULE_SUB_PATH}/run_service.sh" "${MNT_POINT}/firmadyne/run_service.sh" || true
    chmod a+x "${MNT_POINT}/firmadyne/run_service.sh"

    chmod a+x "${MNT_POINT}/firmadyne/init"
    cp "${MNT_POINT}/firmadyne/init" "${LOG_PATH_MODULE}/firmadyne_init"

    CURRENT_DIR=$(pwd)
    cd "${MNT_POINT}" || exit
    mapfile -t NVRAM_FILE_LIST < <(find . -xdev -type f -name "*nvram*")
    for NVRAM_FILE in "${NVRAM_FILE_LIST[@]}"; do
      if file "${NVRAM_FILE}" | grep -q "ASCII text"; then
        if ! [[ -d "${LOG_PATH_MODULE}"/nvram ]]; then
          mkdir "${LOG_PATH_MODULE}"/nvram
        fi
        NVRAM_FILE="${NVRAM_FILE/\.}"
        print_output "[*] Found possible NVRAM default file ${ORANGE}${NVRAM_FILE}${NC} -> setup /firmadyne directory"
        echo "${NVRAM_FILE}" >> "${LOG_PATH_MODULE}"/nvram/nvram_files
        cp ."${NVRAM_FILE}" "${LOG_PATH_MODULE}"/nvram/
      fi
    done
    cd "${CURRENT_DIR}" || exit

  else
    print_output "[!] Filesystem mount failed"
  fi
}

main_emulation() {
  R_PATH="${1:-}"
  ARCH_END="${2:-}"
  BOOTED="NONE"

  create_emulation_filesystem "${R_PATH}" "${ARCH_END}"

  if [[ -f "${LOG_PATH_MODULE}"/firmadyne_init ]]; then
    print_output "[*] Processing init files:"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/firmadyne_init
    readarray -t INIT_FILES < "${LOG_PATH_MODULE}"/firmadyne_init
  else
    print_output "[-] WARNING: init file not created!"
  fi

  INDEX=1
  BAK_INIT_BACKUP=""
  BAK_INIT_ORIG=""
  local INIT_OUT=""
  export IPS_INT_VLAN=()

  for INIT_FILE in "${INIT_FILES[@]}"; do
    INIT_FNAME=$(basename "${INIT_FILE}")
    # this is the main init entry - we modify it later for special cases:
    KINIT="rdinit=/firmadyne/preInit.sh"

    print_bar ""
    print_output "[*] Processing init file ${ORANGE}${INIT_FILE}${NC} (${INDEX}/${#INIT_FILES[@]})"
    if ! mount | grep -q "${MNT_POINT}"; then
      DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
      if [[ "${DEVICE}" == "NA" ]]; then
        DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
      fi
      if [[ "${DEVICE}" == "NA" ]]; then
        print_output "[-] No Qemu Image device identified"
        break
      fi
      sleep 1
      print_output "[*] Device mapper created at ${ORANGE}${DEVICE}${NC}"
      print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
      mount "${DEVICE}" "${MNT_POINT}" || true
    fi

    if [[ -n "${BAK_INIT_ORIG}" ]]; then
      print_output "[*] Restoring old init file: ${BAK_INIT_ORIG}"
      cp -pr "${BAK_INIT_BACKUP}" "${BAK_INIT_ORIG}"
      BAK_INIT_BACKUP=""
      BAK_INIT_ORIG=""
    fi
 
    print_output "[*] Init file details:"
    file "${MNT_POINT}""${INIT_FILE}" | tee -a "${LOG_FILE}"

    # This is just as backup:
    INIT_OUT="${MNT_POINT}""/firmadyne/preInit.sh"
    # we deal with something which is not a script:
    if file "${MNT_POINT}""${INIT_FILE}" | grep -q "symbolic link\|ELF"; then
      # e.g. netgear R6200
      # KINIT="init=/firmadyne/preInit.sh"
      KINIT="${KINIT:2}"
      # write the init ELF file or sym link to the firmadyne preInit script:
      INIT_OUT="${MNT_POINT}""/firmadyne/preInit.sh"

      print_output "[*] Backup original init file ${ORANGE}${INIT_OUT}${NC}"
      BAK_INIT_ORIG="${INIT_OUT}"
      BAK_INIT_BACKUP="${LOG_PATH_MODULE}"/"$(basename "${INIT_OUT}".init)"
      cp -pr "${INIT_OUT}" "${BAK_INIT_BACKUP}"

      print_output "[*] Add ${INIT_FILE} entry to ${ORANGE}${INIT_OUT}${NC}"
      echo "${INIT_FILE} &" >> "${INIT_OUT}" || true
    fi

    # we deal with a startup script
    local FS_MOUNTS_INIT=()
    if file "${MNT_POINT}""${INIT_FILE}" | grep -q "text executable\|ASCII text"; then
      INIT_OUT="${MNT_POINT}""${INIT_FILE}"
      find "${INIT_OUT}" -xdev -maxdepth 1 -ls || true
      print_output "[*] Backup original init file ${ORANGE}${INIT_OUT}${NC}"
      BAK_INIT_ORIG="${INIT_OUT}"
      BAK_INIT_BACKUP="${LOG_PATH_MODULE}"/"$(basename "${INIT_OUT}".init)"
      cp -pr "${INIT_OUT}" "${BAK_INIT_BACKUP}"

      mapfile -t FS_MOUNTS_INIT < <(grep -E "^mount\ -t\ .*\ .*mtd.* /.*" "${INIT_OUT}" | sort -u || true)

      # just in case we have issues with permissions
      chmod +x "${INIT_OUT}"

      # just in case there is an exit in the init -> comment it
      sed -i -r 's/(.*exit\ [0-9])$/\#\ \1/' "${INIT_OUT}"
    fi

    # Beside the check of init we also try to find other mounts for further filesystems
    # probably we need to tweak this further to also find mounts in binaries - strings?!?
    local FS_MOUNTS_FS=()
    if [[ -d "${FIRMWARE_PATH}" ]]; then
      mapfile -t FS_MOUNTS_FS < <(find "${FIRMWARE_PATH}"  -xdev -type f -exec grep -a -h -E "^mount\ -t\ .*\ .*mtd.* /.*" {} \; 2>/dev/null | sort -u || true)
    fi

    FS_MOUNTS=( "${FS_MOUNTS_INIT[@]}" "${FS_MOUNTS_FS[@]}" )
    eval "FS_MOUNTS=($(for i in "${FS_MOUNTS[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
    handle_fs_mounts "${FS_MOUNTS[@]}"

    print_output "[*] Add network.sh entry to ${ORANGE}${INIT_OUT}${NC}"

    echo "" >> "${INIT_OUT}" || true
    echo "/firmadyne/network.sh &" >> "${INIT_OUT}" || true

    if [[ -f "${MNT_POINT}/firmadyne/service" ]]; then
      while read -r SERVICE_NAME; do
        print_output "[*] Created service entry for starting service ${ORANGE}${SERVICE_NAME}${NC}"
      done < "${MNT_POINT}/firmadyne/service"
      echo "/firmadyne/run_service.sh &" >> "${INIT_OUT}" || true
    fi

    # trendnet TEW-828DRU_1.0.7.2, etc...
    echo "/firmadyne/busybox sleep 36000" >> "${INIT_OUT}" || true

    print_output "[*] Current init file: ${ORANGE}${INIT_OUT}${NC}"
    tee -a "${LOG_FILE}" < "${INIT_OUT}"

    print_ln
    print_output "[*] FirmAE filesytem:"
    find "${MNT_POINT}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}" || true

    print_ln
    print_output "[*] FirmAE firmadyne directory:"
    find "${MNT_POINT}"/firmadyne -xdev -ls | tee -a "${LOG_FILE}" || true
    print_ln

    ### set default network values for network identification mode
    IP_ADDRESS_="192.168.0.1"
    NETWORK_MODE="None"
    NETWORK_DEVICE="br0"
    ETH_INT="eth0"
    set_network_config "${IP_ADDRESS_}" "${NETWORK_MODE}" "${NETWORK_DEVICE}" "${ETH_INT}"

    print_output "[*] Unmounting QEMU Image"
    umount_qemu_image "${DEVICE}"

    check_qemu_instance_l10

    identify_networking_emulation "${IMAGE_NAME}" "${ARCH_END}"
    get_networking_details_emulation "${IMAGE_NAME}"

    print_output "[*] Firmware ${ORANGE}${IMAGE_NAME}${NC} finished for identification of the network configuration"

    local F_STARTUP=0
    if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
      cat "${LOG_PATH_MODULE}"/qemu.initial.serial.log >> "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}".log
      write_link "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}".log

      ###############################################################################################
      # if we were running into issues with the network identification we poke with rdinit vs init:
      # lets check if we have found a startup procedure (preInit script) from EMBA - if not we try it with the other init
      F_STARTUP=$(grep -a -c "EMBA preInit script starting" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)
      F_STARTUP=$(( "${F_STARTUP}" + "$(grep -a -c "Network configuration - ACTION" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)" ))
    else
      print_output "[-] No Qemu log file generated ... some weird error occured"
      return
    fi
    # print_output "[*] Found $ORANGE$F_STARTUP$NC EMBA startup entries."
    print_ln

    if [[ "${#PANICS[@]}" -gt 0 ]] || [[ "${F_STARTUP}" -eq 0 ]] || [[ "${DETECTED_IP}" -eq 0 ]]; then
      # if we are running into a kernel panic during the network detection we are going to check if the
      # panic is caused from an init failure. If so, we are trying the other init kernel command (init vs rdinit)
      if [[ "${PANICS[*]}" == *"Kernel panic - not syncing: Attempted to kill init!"* || "${PANICS[*]}" == *"Kernel panic - not syncing: No working init found."* ]]; then
        mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_base_init.log
        if [[ "${KINIT}" == "rdinit="* ]]; then
          print_output "[*] Warning: Kernel panic with failed rdinit found - testing init"
          # strip rd from rdinit
          KINIT="${KINIT:2}"
        else
          print_output "[*] Warning: Kernel panic with failed init found - testing rdinit"
          # make rdinit from init
          KINIT="rd""${KINIT}"
        fi
        # re-identify the network via other init configuration
        identify_networking_emulation "${IMAGE_NAME}" "${ARCH_END}"
        get_networking_details_emulation "${IMAGE_NAME}"

        print_output "[*] Firmware ${ORANGE}${IMAGE_NAME}${NC} finished for identification of the network configuration"
        if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
          mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_new_init.log
          write_link "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_new_init.log
        else
          print_output "[-] No Qemu log file generated ... some weird error occured"
        fi
        print_ln

      elif [[ "${F_STARTUP}" -eq 0 && "${NETWORK_MODE}" == "None" ]] || \
        [[ "${F_STARTUP}" -eq 0 && "${NETWORK_MODE}" == "default" ]] || [[ "${DETECTED_IP}" -eq 0 ]]; then
        mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_base_init.log
        COUNTING_1st=$(wc -l "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_base_init.log | awk '{print $1}')
        PORTS_1st=$(grep -a "inet_bind" "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_base_init.log | sort -u | wc -l | awk '{print $1}' || true)
        if [[ "${KINIT}" == "rdinit="* ]]; then
          print_output "[*] Warning: Unknown EMBA startup found via rdinit - testing init"
          # strip rd from rdinit
          KINIT="${KINIT:2}"
        else
          print_output "[*] Warning: Unknown EMBA startup found via init - testing rdinit"
          # make rdinit from init
          KINIT="rd""${KINIT}"
        fi

        # re-identify the network via other init configuration
        identify_networking_emulation "${IMAGE_NAME}" "${ARCH_END}"
        get_networking_details_emulation "${IMAGE_NAME}"

        if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
          # now we need to check if something is better now or we should switch back to the original init
          F_STARTUP=$(grep -a -c "EMBA preInit script starting" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)
          F_STARTUP=$(( "${F_STARTUP}" + "$(grep -a -c "Network configuration - ACTION" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)" ))
          COUNTING_2nd=$(wc -l "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk '{print $1}')
          PORTS_2nd=$(grep -a "inet_bind" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | sort -u | wc -l | awk '{print $1}' || true)
          # IPS_INT_VLAN is always at least 1 for the default configuration
        else
          F_STARTUP=0
          COUNTING_2nd=0
          PORTS_2nd=0
        fi
        if [[ "${#PANICS[@]}" -gt 0 ]] || [[ "${F_STARTUP}" -eq 0 && "${#IPS_INT_VLAN[@]}" -lt 2 ]] || \
          [[ "${DETECTED_IP}" -eq 0 ]]; then
          if [[ "${PORTS_1st}" -gt "${PORTS_2nd}" ]]; then
            if [[ "${KINIT}" == "rdinit="* ]]; then
              print_output "[*] Warning: switching back to init (identified services - ${PORTS_1st} / ${PORTS_2nd})"
              # strip rd from rdinit
              KINIT="${KINIT:2}"
            else
              print_output "[*] Warning: switching back to rdinit (identified services - ${PORTS_1st} / ${PORTS_2nd})"
              # make rdinit from init
              KINIT="rd""${KINIT}"
            fi
          # we only switch back if the first check has more output generated
          elif [[ "${COUNTING_1st}" -gt "${COUNTING_2nd}" ]] && [[ "${PORTS_1st}" -ge "${PORTS_2nd}" ]]; then
            if [[ "${KINIT}" == "rdinit="* ]]; then
              print_output "[*] Warning: switching back to init (generated log output)"
              # strip rd from rdinit
              KINIT="${KINIT:2}"
            else
              print_output "[*] Warning: switching back to rdinit (generated log output)"
              # make rdinit from init
              KINIT="rd""${KINIT}"
            fi
          fi
        fi

        print_output "[*] Firmware ${ORANGE}${IMAGE_NAME}${NC} finished for identification of the network configuration"
        if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
          mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_new_init.log
          write_link "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${INIT_FNAME}"_new_init.log
        else
          print_output "[-] No Qemu log file generated ... some weird error occured"
        fi
        print_ln

        PANICS=()
      fi
    fi
    ###############################################################################################

    if [[ "${#IPS_INT_VLAN[@]}" -gt 0 && "${#PANICS[@]}" -eq 0 ]]; then
      nvram_check "${IMAGE_NAME}"
      print_bar ""
      print_output "[*] Identified the following network configuration options:"
      local IP_CFG=""
      local INTERFACE_CFG=""
      local NETWORK_INTERFACE_CFG=""
      local VLAN_CFG=""
      local CFG_CFG=""
      for IPS_INT_VLAN_CFG in "${IPS_INT_VLAN[@]}"; do
        IP_CFG=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f1)
        INTERFACE_CFG=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f2)
        NETWORK_INTERFACE_CFG=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f3)
        VLAN_CFG=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f4)
        CFG_CFG=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f5)
        print_output "$(indent "$(orange "${IP_CFG}"" - ""${INTERFACE_CFG}"" - ""${NETWORK_INTERFACE_CFG}"" - ""${VLAN_CFG}"" - ""${CFG_CFG}")")"
      done

      for IPS_INT_VLAN_CFG in "${IPS_INT_VLAN[@]}"; do
        SYS_ONLINE=0

        IPS_INT_VLAN_CFG_MOD=$(echo "${IPS_INT_VLAN_CFG}" | tr ';' '-')
        print_ln
        print_output "[*] Testing system emulation with configuration: ${ORANGE}${IPS_INT_VLAN_CFG_MOD}${NC}."

        cleanup_tap
        DEP_ERROR=0
        check_emulation_port "Running Qemu service" "2001"
        if [[ "${DEP_ERROR}" -eq 1 ]]; then
          while true; do
            DEP_ERROR=0
            check_emulation_port "Running Qemu service" "2001"
            if [[ "${DEP_ERROR}" -ne 1 ]]; then
              break
            fi
            print_output "[-] Is there some Qemu instance already running?"
            print_output "[-] Check TCP ports 2000 - 2003!"
            sleep 10
          done
        fi

        setup_network_emulation "${IPS_INT_VLAN_CFG}"
        run_emulated_system "${IP_ADDRESS_}" "${IMAGE_NAME}"

        IP_ADDRESS_=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f1)
        IPS_INT_VLAN_CFG_mod=$(echo "${IPS_INT_VLAN_CFG}" | tr ';' '-')
        NMAP_LOG="nmap_emba_${IPS_INT_VLAN_CFG_mod}.txt"

        check_online_stat "${IP_ADDRESS_}" "${NMAP_LOG}" &
        CHECK_ONLINE_STAT_PID="$!"

        # we kill this process from "check_online_stat:"
        tail -F "${LOG_PATH_MODULE}/qemu.final.serial.log" 2>/dev/null || true
        kill -9 "${CHECK_ONLINE_STAT_PID}" || true

        # set default state
        ICMP="not ok"
        TCP_0="not ok"
        TCP="not ok"
        if [[ -f "${TMP_DIR}"/online_stats.tmp ]]; then
          if grep -q -E "Host with .* is reachable via ICMP." "${TMP_DIR}"/online_stats.tmp; then
            ICMP="ok"
            SYS_ONLINE=1
            BOOTED="yes"
          fi
          if grep -q -E "Host with .* is reachable on TCP port 0 via hping." "${TMP_DIR}"/online_stats.tmp; then
            TCP_0="ok"
            SYS_ONLINE=1
            BOOTED="yes"
          fi
          if grep -q "tcp.*open" "${ARCHIVE_PATH}"/"${NMAP_LOG}" 2>/dev/null; then
            TCP="ok"
            SYS_ONLINE=1
            BOOTED="yes"
          fi

          # remove tmp files for next round
          rm "${TMP_DIR}"/online_stats.tmp || true
        fi

        RESULT_SOURCE="EMBA"
        write_results "${ARCHIVE_PATH}" "${R_PATH}"

        # if we are going to execute L15 then we do not reset the network environment now
        # we just write the commands to run.sh
        if function_exists L99_cleanup; then
          # L99_cleanup module is loaded and we do not reset the network now
          EXECUTE=0
        else
          EXECUTE=1
        fi
        # reset_network_emulation "${EXECUTE}"
        cleanup_emulator "${IMAGE_NAME}"
              
        if [[ -f "${LOG_PATH_MODULE}"/qemu.final.serial.log ]]; then
          mv "${LOG_PATH_MODULE}"/qemu.final.serial.log "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${IPS_INT_VLAN_CFG_mod}"-"${INIT_FNAME}".log
        fi

        if [[ "${SYS_ONLINE}" -eq 1 ]]; then
          print_ln
          print_output "[+] System emulation was successful."
          if [[ -f "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${IPS_INT_VLAN_CFG_mod}"-"${INIT_FNAME}".log ]]; then
            print_output "[+] System should be available via IP ${ORANGE}${IP_ADDRESS_}${GREEN}." "" "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${IPS_INT_VLAN_CFG_mod}"-"${INIT_FNAME}".log
          else
            print_output "[+] System should be available via IP ${ORANGE}${IP_ADDRESS_}${GREEN}."
          fi
          print_ln

          if [[ "${TCP}" == "ok" ]]; then
            print_output "[+] Network services are available." "" "${ARCHIVE_PATH}/${NMAP_LOG}"
            print_ln
          fi

          create_emulation_archive "${ARCHIVE_PATH}"

          # if we have a working emulation we stop here
          if [[ "${TCP}" == "ok" ]]; then
            if [[ $(grep "udp.*open\ \|tcp.*open\ " "${ARCHIVE_PATH}"/"${NMAP_LOG}" 2>/dev/null | awk '{print $1}' | sort -u | wc -l || true) -gt 2 ]]; then
              # we only exit if we have more than 1 open port detected.
              # Otherwise we try to find a better solution
              # We stop the emulation now and restart it later on
              stopping_emulation_process "${IMAGE_NAME}"
              # if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
              #  reset_network_emulation 1
              # else
              #  print_output "[-] No startup script ${ORANGE}$ARCHIVE_PATH/run.sh${NC} found - this should not be possible!"
              #  reset_network_emulation 2
              # fi
              if [[ "${DEBUG_MODE}" -ne 1 ]]; then
                break 2
              fi
            fi
          fi
        else
          print_output "[-] No working emulation - removing emulation archive."
          if [[ "${DEBUG_MODE}" -ne 1 ]]; then
            create_emulation_archive "${ARCHIVE_PATH}"
          else
            # print_output "[-] Emulation archive: $ARCHIVE_PATH."
            # create_emulation_archive "$ARCHIVE_PATH"
            rm -r "${ARCHIVE_PATH}" || true
          fi
        fi

        stopping_emulation_process "${IMAGE_NAME}"
        # if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
        #  reset_network_emulation 1
        # else
        #  reset_network_emulation 2
        # fi

        if [[ -f "${LOG_PATH_MODULE}"/nvram/nvram_files_final_ ]]; then
          mv "${LOG_PATH_MODULE}"/nvram/nvram_files_final_ "${LOG_PATH_MODULE}"/nvram/nvram_files_"${IMAGE_NAME}".bak
        fi
        if ! [[ -f "${LOG_PATH_MODULE}/qemu.final.serial_${IMAGE_NAME}-${IPS_INT_VLAN_CFG_mod}-${INIT_FNAME}.log" ]]; then
          print_output "[!] Warning: No Qemu log file generated for ${ORANGE}${IMAGE_NAME}-${IPS_INT_VLAN_CFG_mod}-${INIT_FNAME}${NC}"
        fi
      done
    else
      print_output "[!] No further emulation steps are performed"
    fi

    cleanup_emulator "${IMAGE_NAME}"

    print_output "[*] Processing init file ${ORANGE}${INIT_FILE}${NC} (${INDEX}/${#INIT_FILES[@]}) finished"
    print_bar ""
    sleep 1
    ((INDEX+=1))
  done

  delete_device_entry "${IMAGE_NAME}" "${DEVICE}" "${MNT_POINT}"
}

umount_qemu_image() {
  local DEVICE_=${1:-}
  sync
  disable_strict_mode "${STRICT_MODE}" 0
  if ! umount "${DEVICE_}"; then
    print_output "[*] Warning: Normal umount was not successful. Trying to enforce unmounting of ${ORANGE}${DEVICE_}${NC}."
    umount -l "${DEVICE_}" || true
    umount -f "${DEVICE_}" || true
    sleep 5
  fi
  enable_strict_mode "${STRICT_MODE}" 0
  delete_device_entry "${IMAGE_NAME}" "${DEVICE_}" "${MNT_POINT}"
}

handle_fs_mounts() {
  # WARNING: This code needs to be adjusted and tested
  # Currently it was created for the TP-Link camera set (at the end it was not working as expected!)
  # Idea: we identify areas that are mounted during bootup process:
  # mount -t jffs2 /dev/mtdblock5 /usr/local
  # mount -t jffs2 /dev/mtdblock6 /usr/local/config/ipcamera
  # Next we are trying to find them in the extracted data. If we identify something
  # with jffs2 in the name we copy it to the original root filesystem
  # This is very dirty but if it works ... it works ;)
  local FS_MOUNTS=("$@")

  for FS_MOUNT in "${FS_MOUNTS[@]}"; do
    local MOUNT_PT=""
    local MOUNT_FS=""
    local FS_FIND=""

    print_output "[*] Found filesystem mount and analysing it: ${ORANGE}${FS_MOUNT}${NC}"
    # as the original mount will not work, we need to remove it from the startup file:
    sed -i 's|'"${FS_MOUNT}"'|\#'"${FS_MOUNT}"'|g' "${MNT_POINT}""${INIT_FILE}"

    MOUNT_PT=$(echo "${FS_MOUNT}" | awk '{print $5}')
    MOUNT_FS=$(echo "${FS_MOUNT}" | grep " \-t " | sed 's/.*-t //g' | awk '{print $1}')
    if [[ "${MOUNT_FS}" != *"jffs"* ]] && [[ "${MOUNT_FS}" != *"cramfs"* ]]; then
      print_output "[-] Warning: ${ORANGE}${MOUNT_FS}${NC} filesystem currently not supported"
      print_output "[-] Warning: If further results are wrong please open a ticket"
    fi
    if [[ "${MOUNT_PT}" != *"/"* ]]; then
      MOUNT_PT=$(echo "${FS_MOUNT}" | awk '{print $NF}')
      if [[ "${MOUNT_PT}" != *"/"* ]]; then
        print_output "[-] Warning: Mount point ${ORANGE}${MOUNT_PT}${NC} currently not supported"
        print_output "[-] Warning: If further results are wrong please open a ticket"
      fi
    fi
    # we test for paths including the MOUNT_FS part like "jffs2" in the path
    FS_FIND=$(find "${LOG_DIR}"/firmware -path "*/*${MOUNT_FS}*_extract" | head -1 || true)

    print_output "[*] Identified mount point: ${ORANGE}${MOUNT_PT}${NC}"
    print_output "[*] Identified mounted fs: ${ORANGE}${MOUNT_FS}${NC}"

    if [[ "${FS_FIND}" =~ ${MOUNT_FS} ]]; then
      print_output "[*] Possible FS target found: ${ORANGE}${FS_FIND}${NC}"
    else
      print_output "[-] No FS target found"
    fi
    print_output "[*] Root system mount point: ${ORANGE}${MNT_POINT}${NC}"

    if [[ "${R_PATH}" == *"${FS_FIND}"* ]]; then
      print_output "[-] Found our own root directory ... skipping"
      print_output "[*] R_PATH: ${R_PATH}"
      print_output "[*] FS_FIND: ${FS_FIND}"
      continue
    fi

    find "${FS_FIND}" -xdev -ls || true

    print_output "[*] Identify system areas in the to-mount area:"
    local LINUX_PATHS=( "bin" "boot" "dev" "etc" "home" "lib" "mnt" "opt" "proc" "root" "sbin" "srv" "tmp" "usr" "var" )
    for L_PATH in "${LINUX_PATHS[@]}"; do
      mapfile -t NEWPATH_tmp < <(find "${FS_FIND}" -path "*/${L_PATH}" -type d | sed "s/\/${L_PATH}\/*/\//g")
      mapfile -t NEWPATH_test < <(find "${FS_FIND}" -path "*/${L_PATH}" -type d)
      NEWPATH+=( "${NEWPATH_tmp[@]}" )
      if [[ -d "${MNT_POINT}"/"${L_PATH}" ]]; then
        for X_PATH in "${NEWPATH_test[@]}"; do
          print_output "[*] Copy ${X_PATH} to ${MNT_POINT}/${L_PATH}/"
          cp -prn "${X_PATH}"/* "${MNT_POINT}"/"${L_PATH}"/
        done
      fi
    done

    eval "NEWPATH=($(for i in "${NEWPATH[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

    for N_PATH in "${NEWPATH[@]}"; do
      if [[ -z "${N_PATH}" ]]; then
        continue
      fi
      print_output "[*] PATH found: ${N_PATH}"
      find "${N_PATH}" -xdev -ls || true

      if ! [[ -d "${MNT_POINT}""${MOUNT_PT}" ]]; then
        print_output "[*] Creating target directory ${MNT_POINT}${MOUNT_PT}"
        mkdir -p "${MNT_POINT}""${MOUNT_PT}"
      fi
      print_output "[*] Let's copy the identified area to the root filesystem - ${ORANGE}${N_PATH}${NC} to ${ORANGE}${MNT_POINT}${MOUNT_PT}${NC}"
      cp -prn "${N_PATH}"* "${MNT_POINT}""${MOUNT_PT}"
      find "${MNT_POINT}""${MOUNT_PT}" -xdev -ls || true
    done

    print_output "[*] Final copy of ${ORANGE}${FS_FIND}${NC} to ${ORANGE}${MNT_POINT}${MOUNT_PT}${NC} ..."
    cp -prn "${FS_FIND}"/* "${MNT_POINT}""${MOUNT_PT}"
    # find "$MNT_POINT""$MOUNT_PT" -xdev -ls || true
    ls -lh "${MNT_POINT}""${MOUNT_PT}"
  done

  # Todo: move this to somewhere, where we only need to do this once
  print_output "[*] Fix script and ELF permissions - again"
  readarray -t BINARIES_L10 < <( find "${MNT_POINT}" -xdev -type f -exec file {} \; 2>/dev/null | grep "ELF\|executable" | cut -d: -f1 || true)
  for BINARY_L10 in "${BINARIES_L10[@]}"; do
    [[ -x "${BINARY_L10}" ]] && continue
    if [[ -f "${BINARY_L10}" ]]; then
      chmod +x "${BINARY_L10}"
    fi
  done

  # now we need to startup the inferFile/inferService script again
  cp "$(command -v bash-static)" "${MNT_POINT}" || true
  cp "$(command -v busybox)" "${MNT_POINT}" || true
  cp "${MODULE_SUB_PATH}/inferService.sh" "${MNT_POINT}" || true
  print_output "[*] inferService.sh (chroot)"
  FIRMAE_BOOT=${FIRMAE_BOOT} FIRMAE_ETC=${FIRMAE_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /bash-static /inferService.sh | tee -a "${LOG_FILE}"
  rm "${MNT_POINT}"/inferService.sh || true
  rm "${MNT_POINT}"/bash-static|| true
  rm "${MNT_POINT}"/busybox || true

  if [[ -f "${MNT_POINT}"/firmadyne/service ]]; then
    # tp-link camset fix (e.g. NC200_2.1.8_Build_171109_Rel.28679.bin):
    if grep -q "lighttpd" "${MNT_POINT}"/firmadyne/service; then
      if ! [[ -d "${MNT_POINT}"/var/run/lighttpd ]]; then
        print_output "[*] Creating pid directory for lighttpd service"
        mkdir -p "${MNT_POINT}"/var/run/lighttpd || true
      fi
    fi
  fi
}

cleanup_emulator(){
  local IMAGE_NAME="${1:-}"
  if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
    reset_network_emulation 1
  else
    reset_network_emulation 2
  fi

  # ugly cleanup:
  rm /tmp/qemu."${IMAGE_NAME}" || true
  rm /tmp/qemu."${IMAGE_NAME}".S1 || true
  rm /tmp/do_not_create_run.sh || true

  # losetup
  losetup -D
}

delete_device_entry() {
  local IMAGE_NAME="${1:-}"
  local DEVICE="${2:-}"
  local MNT_POINT="${3:-}"

  print_output "[*] Deleting device mapper" "no_log"

  kpartx -v -d "${LOG_PATH_MODULE}/${IMAGE_NAME}"
  losetup -d "${DEVICE}" &>/dev/null || true
  # just in case we check the output and remove our device:
  if losetup | grep -q "$(basename "${IMAGE_NAME}")"; then
    losetup -d "$(losetup | grep "$(basename "${IMAGE_NAME}")" | awk '{print $1}' || true)"
  fi
  dmsetup remove "$(basename "${DEVICE}")" &>/dev/null || true
  rm -rf "${MNT_POINT:?}/"* || true
  sleep 1
}

identify_networking_emulation() {
  # based on the original firmadyne and FirmAE script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/inferNetwork.sh

  sub_module_title "Network identification"
  IMAGE_NAME="${1:-}"
  IMAGE=$(abs_path "${LOG_PATH_MODULE}/${IMAGE_NAME}")

  ARCH_END="${2:-}"

  print_output "[*] Test basic emulation and identify network settings.\\n"
  print_output "[*] Running firmware ${ORANGE}${IMAGE_NAME}${NC}: Terminating after 660 secs..."

  QEMU_PARAMS=""
  CPU=""
  CONSOLE="ttyS0"
  if [[ "${ARCH_END}" == "mipsel" ]]; then
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-mipsel"
    MACHINE="malta"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "mips64r2el" ]]; then
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-mips64el"
    CPU="-cpu MIPS64R2-generic"
    MACHINE="malta"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "mipseb" ]]; then
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-mips"
    MACHINE="malta"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "mips64r2eb" ]]; then
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-mips64"
    CPU="-cpu MIPS64R2-generic"
    MACHINE="malta"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "mips64v1eb" ]]; then
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-mips64"
    # CPU="-cpu MIPS64R2-generic"
    MACHINE="malta"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "mips64v1el" ]]; then
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-mips64el"
    # CPU="-cpu MIPS64R2-generic"
    MACHINE="malta"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "mips64n32eb" ]]; then
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-mips64"
    CPU="-cpu MIPS64R2-generic"
    MACHINE="malta"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "armel"* ]]; then
    KERNEL_="zImage"
    QEMU_BIN="qemu-system-arm"
    MACHINE="virt"
    QEMU_DISK="-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    QEMU_ROOTFS="/dev/vda1"
    QEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev user,id=net0"
    # QEMU_NETWORK="-device virtio-net-device,netdev=net1 -netdev socket,listen=:2000,id=net1 -device virtio-net-device,netdev=net2 -netdev socket,listen=:2001,id=net2 -device virtio-net-device,netdev=net3 -netdev socket,listen=:2002,id=net3 -device virtio-net-device,netdev=net4 -netdev socket,listen=:2003,id=net4"
    # QEMU_PARAMS="-audiodev driver=none,id=none"
  elif [[ "${ARCH_END}" == "arm64el"* ]]; then
    KERNEL_="Image"
    QEMU_BIN="qemu-system-aarch64"
    MACHINE="virt"
    CPU="-cpu cortex-a57"
    # CONSOLE="ttyAMA0"
    QEMU_DISK="-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    QEMU_ROOTFS="/dev/vda1"
    QEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev user,id=net0"
  elif [[ "${ARCH_END}" == "x86el"* ]]; then
    KERNEL_="bzImage"
    QEMU_BIN="qemu-system-x86_64"
    MACHINE="pc-i440fx-3.1"
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1 -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2 -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"
  elif [[ "${ARCH_END}" == "nios2el" ]]; then
    # not implemented -> Future
    KERNEL_="vmlinux"
    QEMU_BIN="qemu-system-nios2"
    MACHINE="10m50-ghrd"
    QEMU_DISK="-drive file=${IMAGE},format=raw"
    QEMU_ROOTFS="/dev/sda1"
    QEMU_PARAMS="-monitor none"
    QEMU_NETWORK=""
  else
    print_output "[-] WARNING: No supported configuration found for ${ORANGE}${ARCH_END}${NC}."
    return
  fi

  run_network_id_emulation &
  PID="$!"
  disown "${PID}" 2> /dev/null || true
  run_kpanic_identification &
  KPANIC_PID="$!"
  disown "${KPANIC_PID}" 2> /dev/null || true

  timeout --preserve-status --signal SIGINT 660 tail -F "${LOG_PATH_MODULE}/qemu.initial.serial.log" 2>/dev/null || true
  PID="$!"
  disown "${PID}" 2> /dev/null || true

  stopping_emulation_process "${IMAGE_NAME}"
  cleanup_emulator "${IMAGE_NAME}"
  # if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
  #  reset_network_emulation 1
  # else
  #  reset_network_emulation 2
  # fi

  if ! [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
    print_output "[-] No ${ORANGE}${LOG_PATH_MODULE}/qemu.initial.serial.log${NC} log file generated."
  fi
  kill -9 "${KPANIC_PID}" >/dev/null || true
}

run_kpanic_identification() {
  # this function identifies kernel panics and stops the further process to save time
  # and not to run 600 secs of network identification a kernel panic
  local COUNTER=0
  # wait until we have a log file
  sleep 5
  while [[ "${COUNTER}" -lt 6 ]]; do
    if grep -a -q "Kernel panic - " "${LOG_PATH_MODULE}/qemu.initial.serial.log"; then
      print_output "[*] Kernel Panic detected - stopping emulation"
      pkill -9 -f tail.*-F.*"${LOG_PATH_MODULE}/qemu.initial.serial.log" || true &>/dev/null
      break
    fi
    sleep 5
    ((COUNTER+=1))
  done
}

run_network_id_emulation() {
  print_output "[*] Qemu network identification run for ${ORANGE}${ARCH_END}${NC} - ${ORANGE}${IMAGE_NAME}${NC}"

  # temp code for future use - currently only kernel v4 is supported
  if [[ "${ARCH_END}" == *"mips"* ]]; then
    KERNEL_V=""
    get_kernel_version
    if [[ -n "${KERNEL_V}" ]]; then
      print_output "[*] Kernel ${KERNEL_V}.x detected -> Using Kernel v4.x"
      KERNEL_V=".${KERNEL_V}"
    else
      KERNEL_V=".4"
    fi
    # hard code v4.x
    KERNEL_V=".4"
    KERNEL="${BINARY_DIR}/${KERNEL_}.${ARCH_END}${KERNEL_V}"
  else
    # ARM architecture
    KERNEL="${BINARY_DIR}/${KERNEL_}.${ARCH_END}"
  fi

  check_qemu_instance_l10

  print_output "[*] Qemu parameters used in network detection mode:"
  print_output "$(indent "MACHINE: ${ORANGE}${MACHINE}${NC}")"
  print_output "$(indent "KERNEL: ${ORANGE}${KERNEL}${NC}")"
  print_output "$(indent "DRIVE: ${ORANGE}${QEMU_DISK}${NC}")"
  print_output "$(indent "KINIT: ${ORANGE}${KINIT}${NC}")"
  print_output "$(indent "ROOT_DEV: ${ORANGE}${QEMU_ROOTFS}${NC}")"
  print_output "$(indent "QEMU binary: ${ORANGE}${QEMU_BIN}${NC}")"
  print_output "$(indent "NETWORK: ${ORANGE}${QEMU_NETWORK}${NC}")"
  print_output "$(indent "Init file: ${ORANGE}${INIT_FILE}${NC}")"
  print_output "$(indent "Console interface: ${ORANGE}${CONSOLE}${NC}")"
  print_ln
  print_output "[*] Starting firmware emulation for network identification - ${ORANGE}${QEMU_BIN} / ${ARCH_END} / ${IMAGE_NAME}${NC} ... use Ctrl-a + x to exit"
  print_ln

  write_script_exec "${QEMU_BIN} -m 2048 -M ${MACHINE} ${CPU} -kernel ${KERNEL} ${QEMU_DISK} -append \"root=${QEMU_ROOTFS} console=${CONSOLE} nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${KINIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} user_debug=0 firmadyne.syscall=1\" -nographic ${QEMU_NETWORK} ${QEMU_PARAMS} -serial file:${LOG_PATH_MODULE}/qemu.initial.serial.log -serial telnet:localhost:4321,server,nowait -serial unix:/tmp/qemu.${IMAGE_NAME}.S1,server,nowait -monitor unix:/tmp/qemu.${IMAGE_NAME},server,nowait ; pkill -9 -f tail.*-F.*\"${LOG_PATH_MODULE}\"" /tmp/do_not_create_run.sh 3
}

get_networking_details_emulation() {
  IMAGE_NAME="${1:-}"

  sub_module_title "Network identification - ${IMAGE_NAME}"
  PANICS=()
  export DETECTED_IP=0

  if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
    ETH_INT="NONE"
    VLAN_ID="NONE"
    NETWORK_MODE="bridge"
    NVRAMS=()
    NVRAM_TMP=()
    TCP_SERVICES_STARTUP=()

    local TCP_PORT=""
    local UDP_PORT=""
  
    mapfile -t INTERFACE_CANDIDATES < <(grep -a "__inet_insert_ifa" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | cut -d: -f2- | sed -E 's/.*__inet_insert_ifa\[PID:\ [0-9]+\ //'| sort -u || true)
    mapfile -t BRIDGE_INTERFACES < <(grep -a "br_add_if\|br_dev_ioctl" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | cut -d: -f4- | sort -u || true)
                #               br_add_if[PID: 246 (brctl)]: br:br0 dev:vlan1
    mapfile -t VLAN_INFOS < <(grep -a "register_vlan_dev" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | cut -d: -f2- | sort -u || true)
    mapfile -t PANICS < <(grep -a "Kernel panic - " "${LOG_PATH_MODULE}"/qemu.initial.serial.log | sort -u || true)
    mapfile -t NVRAM < <(grep -a "\[NVRAM\] " "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk '{print $3}' | grep -a -E '[[:alnum:]]{3,50}' | sort -u || true)
    # mapfile -t NVRAM_SET < <(grep -a "nvram_set" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | cut -d: -f2 | sed 's/^\ //g' | cut -d\  -f1 | sed 's/\"//g' | grep -v "^#" | grep -E '[[:alnum:]]{3,50}'| sort -u || true)
    # we check all available qemu logs for services that are started:
    mapfile -t PORTS < <(grep -a "inet_bind" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | sed -E 's/.*inet_bind\[PID:\ [0-9]+\ //' | sort -u || true)
    mapfile -t VLAN_HW_INFO_DEV < <(grep -a -E "adding VLAN [0-9] to HW filter on device eth[0-9]" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk -F\  '{print $NF}' | sort -u || true)

    # we handle missing files in setup_network_config -> there we already remount the filesystem and we can perform the changes
    mapfile -t MISSING_FILES_TMP < <(grep -a -E "No such file or directory" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | tr ' ' '\n' | grep -a "/" | grep -a -v proc | tr -d ':' | sort -u || true)
    MISSING_FILES+=( "${MISSING_FILES_TMP[@]}" )

    NVRAM_TMP=( "${NVRAM[@]}" )

    if [[ "${#INTERFACE_CANDIDATES[@]}" -gt 0 || "${#BRIDGE_INTERFACES[@]}" -gt 0 || "${#VLAN_INFOS[@]}" -gt 0 || "${#PORTS[@]}" -gt 0 || "${#NVRAM_TMP[@]}" -gt 0 ]]; then
      print_output "[+] Booted system detected."
      BOOTED="yes"
    fi

    if [[ -v NVRAM_TMP[@] ]]; then
      for NVRAM_ENTRY in "${NVRAM_TMP[@]}"; do
        if [[ "${NVRAM_ENTRY}" =~ [[:print:]] ]]; then
          if [[ ! " ${NVRAMS[*]} " =~  ${NVRAM_ENTRY}  ]]; then
            NVRAMS+=( "${NVRAM_ENTRY}" )
          fi
        fi
      done
      print_output "[*] NVRAM access detected ${ORANGE}${#NVRAMS[@]}${NC} times."
      print_ln
    fi

    if [[ -v PORTS[@] ]]; then
      for PORT in "${PORTS[@]}"; do
        SERVICE_NAME=$(strip_color_codes "$(echo "${PORT}" | sed -e 's/.*\((.*)\).*/\1/g' | tr -d "(" | tr -d ")")")
        SERVICE_NAME=$(echo "${SERVICE_NAME}" | tr -dc '[:print:]')
        TCP_PORT=$(strip_color_codes "$(echo "${PORT}" | grep "SOCK_STREAM" | sed 's/.*SOCK_STREAM,\ //' | sort -u | cut -d: -f2)" || true)
        TCP_PORT=$(echo "${TCP_PORT}" | tr -dc '[:print:]')
        UDP_PORT=$(strip_color_codes "$(echo "${PORT}" | grep "SOCK_DGRAM" | sed 's/.*SOCK_DGRAM,\ //' | sort -u | cut -d: -f2)" || true)
        UDP_PORT=$(echo "${UDP_PORT}" | tr -dc '[:print:]')

        if [[ "${TCP_PORT}" =~ [0-9]+ ]]; then
          print_output "[*] Detected TCP service startup: ${ORANGE}${SERVICE_NAME}${NC} / ${ORANGE}${TCP_PORT}${NC}"
          TCP_SERVICES_STARTUP+=( "${TCP_PORT}" )
        fi
        if [[ "${UDP_PORT}" =~ [0-9]+ ]]; then
          print_output "[*] Detected UDP service startup: ${ORANGE}${SERVICE_NAME}${NC} / ${ORANGE}${UDP_PORT}${NC}"
          UDP_SERVICES_STARTUP+=( "${UDP_PORT}" )
        fi

        SERVICES_STARTUP+=( "${SERVICE_NAME}" )
      done
    fi

    eval "SERVICES_STARTUP=($(for i in "${SERVICES_STARTUP[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
    eval "UDP_SERVICES_STARTUP=($(for i in "${UDP_SERVICES_STARTUP[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
    eval "TCP_SERVICES_STARTUP=($(for i in "${TCP_SERVICES_STARTUP[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

    for VLAN_INFO in "${VLAN_INFOS[@]}"; do
      # register_vlan_dev[PID: 128 (vconfig)]: dev:eth1.1 vlan_id:1
      print_output "[*] Possible VLAN details detected: ${ORANGE}${VLAN_INFO}${NC}"
    done

    if [[ -v BRIDGE_INTERFACES[@] ]]; then
      eval "BRIDGE_INTERFACES=($(for i in "${BRIDGE_INTERFACES[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
    fi

    print_ln
    for INTERFACE_CAND in "${INTERFACE_CANDIDATES[@]}"; do
      print_output "[*] Possible interface candidate detected: ${ORANGE}${INTERFACE_CAND}${NC}"
      # INTERFACE_CAND -> __inet_insert_ifa[PID: 139 (ifconfig)]: device:br0 ifa:0xc0a80001
      mapfile -t IP_ADDRESS < <(echo "${INTERFACE_CAND}" | grep device | cut -d: -f2- | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | sed 's/0x//' | sed 's/../0x&\n/g')
      # IP_ADDRESS -> c0a80001
      # as I don't get it to change the hex ip to dec with printf, we do it the poor way:
      IP_=""
      for _IPs in "${IP_ADDRESS[@]}"; do
        if [[ "${_IPs}" == "0x"* ]]; then
          #shellcheck disable=SC2004
          IP_="${IP_}.$((${_IPs}))"
        fi
      done

      IP_="${IP_/\.}"

      IP_ADDRESS_=""
      if [[ "${D_END}" == "eb" ]]; then
        IP_ADDRESS_="${IP_}"
      elif [[ "${D_END}" == "el" ]]; then
        IP_ADDRESS_=$(echo "${IP_}" | tr '.' '\n' | tac | tr '\n' '.' | sed 's/\.$//')
      fi

      # filter for non usable IP addresses:
      if [[ "${IP_ADDRESS_}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ "${IP_ADDRESS_}" == "127."* ]] && ! [[ "${IP_ADDRESS_}" == "0.0.0.0" ]]; then
        print_ln
        print_output "[*] Identified IP address: ${ORANGE}${IP_ADDRESS_}${NC}"
        DETECTED_IP=1
        # get the network device
        NETWORK_DEVICE="$(echo "${INTERFACE_CAND}" | grep device | cut -d: -f2- | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2 | tr -dc '[:print:]' || true)"
        # INTERFACE_CAND -> __inet_insert_ifa[PID: 139 (ifconfig)]: device:br0 ifa:0xc0a80001
        #                   __inet_insert_ifa[PID: 899 (udhcpc)]: device:eth0 ifa:0xbea48f41
        # NETWORK_DEVICE -> eth0, eth1.1, br0 ...

        if [[ -n "${NETWORK_DEVICE}" ]]; then
          # if the network device is not a eth it is a bridge interface
          # if we have BRIDGE_INTERFACES we also check it here (this way we can correct the br interface entry):
          if ! [[ "${NETWORK_DEVICE}" == *"eth"* ]] || [[ -v BRIDGE_INTERFACES[@] ]]; then
            print_output "[*] Possible br interface detected: ${ORANGE}${NETWORK_DEVICE}${GREEN} / IP: ${ORANGE}${IP_ADDRESS_}${NC}"
            NETWORK_MODE="bridge"
            if [[ -v BRIDGE_INTERFACES[@] ]]; then
              for BRIDGE_INT in "${BRIDGE_INTERFACES[@]}"; do
                # BRIDGE_INT -> br_add_if[PID: 494 (brctl)]: br:br0 dev:eth0.1
                #               br_add_if[PID: 246 (brctl)]: br:br0 dev:vlan1
                # NETWORK_DEVICE -> br0
                print_output "[*] Testing bridge interface ${ORANGE}${BRIDGE_INT}${NC}"
                VLAN_ID="NONE"
                # the BRIDGE_INT entry also includes our NETWORK_DEVICE ... eg br:br0 dev:eth1.1
                if [[ "${BRIDGE_INT}" == *"${NETWORK_DEVICE}"* ]]; then
                  # br_add_if[PID: 138 (brctl)]: br:br0 dev:eth1.1
                  # extract the eth1 from dev:eth1
                  # ETH_INT="$(echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "dev:.*" | cut -d. -f1 | cut -d: -f2 | tr -dc '[:print:]')"
                  ETH_INT="$(echo "${BRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f1 | cut -d: -f2 | tr -dc '[:print:]')"
                  # do we have vlans?
                  if [[ -v VLAN_INFOS[@] ]]; then
                    iterate_vlans "${ETH_INT}" "${VLAN_INFOS[@]}"
                  # elif echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]"; then
                  elif echo "${BRIDGE_INT}" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]"; then
                    # we have a vlan entry in our BRIDGE_INT entry br:br0 dev:eth1.1:
                    # VLAN_ID="$(echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "dev:.*" | cut -d. -f2 | tr -dc '[:print:]')"
                    VLAN_ID="$(echo "${BRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f2 | tr -dc '[:print:]')"
                  elif [[ -v VLAN_HW_INFO_DEV[@] ]]; then
                    # if we have found some entry "adding VLAN [0-9] to HW filter on device ethX" in our qemu logs
                    # we check all these entries now and generate additional configurations for further evaluation
                    for ETH_INT_ in "${VLAN_HW_INFO_DEV[@]}"; do
                      # if we found multiple interfaces belonging to a vlan we need to store all of them:
                      ETH_INT_=$(echo "${ETH_INT_}" | tr -dc '[:print:]')
                      VLAN_ID=$(grep -a -o -E "adding VLAN [0-9] to HW filter on device ${ETH_INT_}" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk '{print $3}' | sort -u)
                      # initial entry with possible vlan information
                      store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT_}" "${VLAN_ID}" "${NETWORK_MODE}"

                      # entry with vlan NONE (just in case as backup)
                      store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT_}" "NONE" "${NETWORK_MODE}"

                      if ! [[ "${NETWORK_DEVICE}" == *br[0-9]* ]] && ! [[ "${NETWORK_DEVICE}" == *eth[0-9]* ]]; then
                        # entry with vlan NONE and interface br0 - just as another fallback solution
                        NETWORK_DEVICE_="br0"
                        print_output "[*] Fallback bridge interface - #1 ${ORANGE}${NETWORK_DEVICE_}${NC}"
                        store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE_}" "${ETH_INT_}" "${VLAN_ID}" "${NETWORK_MODE}"
                      fi
                    done
                  else
                    VLAN_ID="NONE"
                  fi
                  # now we set the orig. network_device with the new details:
                  store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"

                  if ! [[ "${NETWORK_DEVICE}" == *br[0-9]* ]] && ! [[ "${NETWORK_DEVICE}" == *eth[0-9]* ]]; then
                    # if we have a bridge device like br-lan we ensure we also have an entry with a usual br0 interface
                    NETWORK_DEVICE_="br0"
                    print_output "[*] Fallback bridge interface - #2 ${ORANGE}${NETWORK_DEVICE_}${NC}"
                    store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE_}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"
                  fi
                  # if we have found that the br entry has for eg an ethX interface, we now check for the real br interface entry -> NETWORK_DEVICE
                  # NETWORK_DEVICE="$(echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "br:.*" | cut -d\  -f1 | cut -d: -f2 | tr -dc '[:print:]')"
                  NETWORK_DEVICE="$(echo "${BRIDGE_INT}" | grep -o "br:.*" | cut -d\  -f1 | cut -d: -f2 | tr -dc '[:print:]')"
                fi
                store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE:-br0}" "${ETH_INT:-eth0}" "${VLAN_ID:-0}" "${NETWORK_MODE:-bridge}"
              done
            else
              # set typical default values - this is just in case we have not found br_add_if entries:
              VLAN_ID="NONE"
              ETH_INT="eth0"
              store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"
            fi
          elif [[ "${NETWORK_DEVICE}" == *"eth"* ]]; then
            print_output "[*] Possible eth network interface detected: ${ORANGE}${NETWORK_DEVICE}${GREEN} / IP: ${ORANGE}${IP_ADDRESS_}${NC}"
            NETWORK_MODE="normal"
            NETWORK_DEVICE="$(echo "${NETWORK_DEVICE}" | cut -d. -f1)"
            ETH_INT="$(echo "${NETWORK_DEVICE}" | cut -d. -f1)"
            if echo "${NETWORK_DEVICE}" | grep -q -E "[0-9]\.[0-9]"; then
              # now we know that there is a vlan number - extract the vlan number now:
              VLAN_ID="$(echo "${NETWORK_DEVICE}" | cut -d. -f2 | grep -E "[0-9]+" | tr -dc '[:print:]')"
            else
              VLAN_ID="NONE"
            fi
            store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"
          else
            # could not happen - just for future extension
            print_output "[+] Possible other interface detected: ${ORANGE}${NETWORK_DEVICE}${NC}"
            VLAN_ID="NONE"
            NETWORK_MODE="normal"
            NETWORK_DEVICE="$(echo "${NETWORK_DEVICE}" | cut -d. -f1)"
            ETH_INT="${NETWORK_DEVICE}"
            store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"
          fi
        fi
        # this is a default (fallback) entry with the correct ip address:
        store_interface_details "${IP_ADDRESS_}" "br0" "eth0" "NONE" "default"
      fi
    done

    if [[ "${#IPS_INT_VLAN[@]}" -eq 0 ]]; then
      # this section is if we have a brctl entry but no IP address
      for BRIDGE_INT in "${BRIDGE_INTERFACES[@]}"; do
        # br_add_if[PID: 138 (brctl)]: br:br0 dev:eth1.1
        # BRIDGE_INT -> br_add_if[PID: 494 (brctl)]: br:br0 dev:eth0.1
        # NETWORK_DEVICE -> br0
        print_output "[*] Possible bridge interface candidate detected: ${ORANGE}${BRIDGE_INT}${NC}"
        # ETH_INT="$(echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "dev:.*" | cut -d. -f1 | cut -d: -f2 | tr -dc '[:print:]' || true)"
        ETH_INT="$(echo "${BRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f1 | cut -d: -f2 | tr -dc '[:print:]' || true)"
        NETWORK_DEVICE="$(echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "br:.*" | cut -d\  -f1 | cut -d: -f2 | tr -dc '[:print:]' || true)"
        IP_ADDRESS_="192.168.0.1"
        NETWORK_MODE="bridge"
        # if echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]"; then
        if echo "${BRIDGE_INT}" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]"; then
          # we have a vlan entry:
          # VLAN_ID="$(echo "${BRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "dev:.*" | cut -d. -f2 | tr -dc '[:print:]' || true)"
          VLAN_ID="$(echo "${BRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f2 | tr -dc '[:print:]' || true)"
        else
          VLAN_ID="NONE"
          if [[ -v VLAN_INFOS[@] ]]; then
            iterate_vlans "${ETH_INT}" "${VLAN_INFOS[@]}"
          fi
        fi
        store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"
      done
    fi

    # fallback - default network configuration:
    # we always add this as the last resort - with this at least ICMP should be possible in most cases
    if [[ ! " ${IPS_INT_VLAN[*]} " =~ "default" ]]; then
      # print_output "[*] No IP address - use default address: ${ORANGE}192.168.0.1${NC}."
      # print_output "[*] No VLAN."
      # print_output "[*] No Network interface - use ${ORANGE}eth0${NC} network."
      IP_ADDRESS_="192.168.0.1"
      NETWORK_MODE="default"
      if [[ "${FW_VENDOR:-}" == "AVM" ]]; then
        # for AVM fritzboxen the default IP is set to the correct one:
        IP_ADDRESS_="192.168.178.1"
      fi
      VLAN_ID="NONE"
      ETH_INT="eth0"
      NETWORK_DEVICE="br0"
      store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"
    fi

    for PANIC in "${PANICS[@]}"; do
      print_output "[!] WARNING: Kernel Panic detected: ${ORANGE}${PANIC}${NC}"
      print_output "${NC}"
    done
    color_qemu_log "${LOG_PATH_MODULE}/qemu.initial.serial.log"
  else
    print_output "[-] No ${ORANGE}${LOG_PATH_MODULE}/qemu.initial.serial.log${NC} log file generated."
  fi
  print_ln
}

store_interface_details() {
  local IP_ADDRESS__="${1:-192.168.0.1}"
  local NETWORK_DEVICE__="${2:-br0}"
  local ETH_INT__="${3:-eth0}"
  local VLAN_ID__="${4:-NONE}"
  local NETWORK_MODE__="${5:-bridge}"

  if [[ "${IPS_INT_VLAN[*]}" == *"${IP_ADDRESS__};${NETWORK_DEVICE__};${ETH_INT__};${VLAN_ID__};${NETWORK_MODE__}"* ]]; then
    return
  fi

  IPS_INT_VLAN+=( "${IP_ADDRESS__}"\;"${NETWORK_DEVICE__}"\;"${ETH_INT__}"\;"${VLAN_ID__}"\;"${NETWORK_MODE__}" )
  print_output "[+] Interface details detected: IP address: ${ORANGE}${IP_ADDRESS__}${GREEN} / bridge dev: ${ORANGE}${NETWORK_DEVICE__}${GREEN} / network device: ${ORANGE}${ETH_INT__}${GREEN} / vlan id: ${ORANGE}${VLAN_ID__}${GREEN} / network mode: ${ORANGE}${NETWORK_MODE__}${NC}"
}

iterate_vlans() {
  local ETH_INT="${1:-}"
  local VLAN_INFOS=("$@")

  local ETH_INT_
  local ETH_INTS=()
  local VLAN_DEV
  local VLAN_ID="NONE"
  local VLAN_INFO

  for VLAN_INFO in "${VLAN_INFOS[@]}"; do
    if ! [[ "${VLAN_INFO}" == *"register_vlan_dev"* ]]; then
      continue
    fi
    # VLAN_INFO -> register_vlan_dev[PID: 848 (vconfig)]: dev:eth2.1 vlan_id:1
    #              register_vlan_dev[PID: 213 (vconfig)]: dev:vlan1 vlan_id:1
    VLAN_DEV=$(echo "${VLAN_INFO}" | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2 | cut -d\. -f1)
    print_output "[*] VLAN details: ${ORANGE}${VLAN_INFO}${NC}"
    print_output "[*] Interface details: ${ORANGE}${ETH_INT}${NC}"
    if [[ "${VLAN_DEV}" == *"${ETH_INT}"* ]]; then
      print_output "[*] Possible matching VLAN details detected: ${ORANGE}${VLAN_INFO}${NC}"
      VLAN_ID=$(echo "${VLAN_INFO}" | sed "s/.*vlan_id://" | grep -E -o "[0-9]+" | tr -dc '[:print:]')
    else
      VLAN_ID="NONE"
    fi
    store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT}" "${VLAN_ID}" "${NETWORK_MODE}"

    # check this later
    # store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "eth0" "${VLAN_ID}" "${NETWORK_MODE}"
    # store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "eth0" "0" "${NETWORK_MODE}"
    # store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "eth1" "${VLAN_ID}" "${NETWORK_MODE}"
    # store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "eth1" "0" "${NETWORK_MODE}"

    # if we have entries without an interface name, we need to identify an interface name:
    # register_vlan_dev[PID: 212 (vconfig)]: dev:vlan1 vlan_id:1
    # for this we try to check the qemu output for vlan entries and generate the configuration entry
    if grep -a -q "adding VLAN [0-9] to HW filter on device eth[0-9]" "${LOG_PATH_MODULE}"/qemu.initial.serial.log; then
      mapfile -t ETH_INTS < <(grep -a -E "adding VLAN [0-9] to HW filter on device eth[0-9]" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk -F\  '{print $NF}' | sort -u)
      for ETH_INT_ in "${ETH_INTS[@]}"; do
        # if we found multiple interfaces belonging to a vlan we need to store all of them:
        ETH_INT_=$(echo "${ETH_INT_}" | tr -dc '[:print:]')
        store_interface_details "${IP_ADDRESS_}" "${NETWORK_DEVICE}" "${ETH_INT_}" "${VLAN_ID}" "${NETWORK_MODE}"
      done
    fi
  done
}

setup_network_emulation() {
  local IPS_INT_VLAN_CFG="${1:-}"

  local IPS_INT_VLAN_CFG_=""
  IPS_INT_VLAN_CFG_=$(echo "${IPS_INT_VLAN_CFG}" | tr ';' '-')
  sub_module_title "Setup networking - ${IPS_INT_VLAN_CFG_}"

  # Source: IPS_INT_VLAN+=( "${IP_ADDRESS_}"-"${NETWORK_DEVICE}"-"${ETH_INT}"-"${VLAN_ID}"-"${NETWORK_MODE}" )
  IP_ADDRESS_=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f1)
  NETWORK_DEVICE=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f2)
  ETH_INT=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f3)
  VLAN_ID=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f4)
  NETWORK_MODE=$(echo "${IPS_INT_VLAN_CFG}" | cut -d\; -f5)

  # a br interface with a number ... eg br0, br1 ... but no br-lan interface
  if [[ "${NETWORK_DEVICE}" == *"br"* ]] && [[ "${NETWORK_DEVICE}" == *[0-9]* ]]; then
    BR_NUM=$(echo "${NETWORK_DEVICE}" | sed -e "s/br//" | tr -dc '[:print:]')
  else
    BR_NUM=0
  fi
  if [[ "${ETH_INT}" == *"eth"* ]]; then
    ETH_NUM=$(echo "${ETH_INT}" | sed -e "s/eth//" | tr -dc '[:print:]')
  else
    ETH_NUM=0
  fi

  # used for generating startup scripts for offline analysis
  export ARCHIVE_PATH="${LOG_PATH_MODULE}"/archive-"${IMAGE_NAME}"-"${RANDOM}"

  if ! [[ -d "${ARCHIVE_PATH}" ]]; then
    mkdir "${ARCHIVE_PATH}"
  fi

  TAP_ID=$(shuf -i 1-1000 -n 1)

  # bridge, no vlan, ip address
  TAPDEV_0="tap${TAP_ID}_0"
  if ifconfig | grep -q "${TAPDEV_0}"; then
    TAP_ID=$(shuf -i 1-1000 -n 1)
    TAPDEV_0="tap${TAP_ID}_0"
  fi
  HOSTNETDEV_0="${TAPDEV_0}"
  print_output "[*] Creating TAP device ${ORANGE}${TAPDEV_0}${NC}..."
  write_script_exec "echo -e \"Creating TAP device ${TAPDEV_0}\n\"" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "command -v tunctl > /dev/null || (echo \"Missing tunctl ... check your installation - install uml-utilities package\" && exit 1)" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "tunctl -t ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh 1

  if [[ "${VLAN_ID}" != "NONE" ]]; then
    HOSTNETDEV_0="${TAPDEV_0}"."${VLAN_ID}"
    print_output "[*] Bringing up HOSTNETDEV ${ORANGE}${HOSTNETDEV_0}${NC} / VLAN ID ${ORANGE}${VLAN_ID}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}."
    write_script_exec "echo -e \"Bringing up HOSTNETDEV ${ORANGE}${HOSTNETDEV_0}${NC} / VLAN ID ${ORANGE}${VLAN_ID}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}.\n\"" "${ARCHIVE_PATH}"/run.sh 0
    write_script_exec "ip link add link ${TAPDEV_0} name ${HOSTNETDEV_0} type vlan id ${VLAN_ID}" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "ip link set ${TAPDEV_0} up" "${ARCHIVE_PATH}"/run.sh 1
  fi

  if [[ "${IP_ADDRESS_}" != "NONE" ]]; then
    HOSTIP="$(echo "${IP_ADDRESS_}" | sed 's/\./&\n/g' | sed -E 's/^[0-9]+$/2/' | tr -d '\n')"
    print_output "[*] Bringing up HOSTIP ${ORANGE}${HOSTIP}${NC} / IP address ${ORANGE}${IP_ADDRESS_}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}."
    write_script_exec "echo -e \"Bringing up HOSTIP ${ORANGE}${HOSTIP}${NC} / IP address ${ORANGE}${IP_ADDRESS_}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}.\n\"" "${ARCHIVE_PATH}"/run.sh 0

    write_script_exec "ip link set ${HOSTNETDEV_0} up" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "ip addr add ${HOSTIP}/24 dev ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "ifconfig -a" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "route -n" "${ARCHIVE_PATH}"/run.sh 1
  fi

  print_ln
  print_output "[*] Current host network:"
  ifconfig | tee -a "${LOG_FILE}"
  print_ln
  write_network_config_to_filesystem
}

write_network_config_to_filesystem() {
  # mount filesystem again for network config:
  print_output "[*] Identify Qemu Image device for ${ORANGE}${LOG_PATH_MODULE}/${IMAGE_NAME}${NC}"
  DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
  if [[ "${DEVICE}" == "NA" ]]; then
    DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
  fi
  if [[ "${DEVICE}" == "NA" ]]; then
    print_output "[-] No Qemu Image device identified"
    return
  fi
  sleep 1
  print_output "[*] Device mapper created at ${ORANGE}${DEVICE}${NC}"
  print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
  mount "${DEVICE}" "${MNT_POINT}" || true
  if mount | grep -q "${MNT_POINT}"; then
    print_output "[*] Setting network configuration in target filesystem:"
    print_output "$(indent "Network interface: ${ORANGE}${ETH_INT}${NC}")"
    print_output "$(indent "Network mode: ${ORANGE}${NETWORK_MODE}${NC}")"
    print_output "$(indent "Bridge interface: ${ORANGE}${NETWORK_DEVICE}${NC}")"
    print_output "$(indent "IP address: ${ORANGE}${IP_ADDRESS_}${NC}")"

    set_network_config "${IP_ADDRESS_}" "${NETWORK_MODE}" "${NETWORK_DEVICE}" "${ETH_INT}"

    # if there were missing files found -> we try to fix this now
    if [[ -v MISSING_FILES[@] ]]; then
      for FILE_PATH_MISSING in "${MISSING_FILES[@]}"; do
        [[ "${FILE_PATH_MISSING}" == *"firmadyne"* ]] && continue
        [[ "${FILE_PATH_MISSING}" == *"/proc/"* ]] && continue
        [[ "${FILE_PATH_MISSING}" == *"/sys/"* ]] && continue
        [[ "${FILE_PATH_MISSING}" == *"/dev/"* ]] && continue
        [[ "${FILE_PATH_MISSING}" == *"reboot"* ]] && continue

        FILENAME_MISSING=$(basename "${FILE_PATH_MISSING}")
        [[ "${FILENAME_MISSING}" == '*' ]] && continue
        print_output "[*] Found missing area ${ORANGE}${FILENAME_MISSING}${NC} in filesystem ... trying to fix this now"
        DIR_NAME_MISSING=$(dirname "${FILE_PATH_MISSING}")
        if ! [[ -d "${MNT_POINT}""${DIR_NAME_MISSING}" ]]; then
          print_output "[*] Create missing directory ${ORANGE}${DIR_NAME_MISSING}${NC} in filesystem ... trying to fix this now"
          mkdir -p "${MNT_POINT}""${DIR_NAME_MISSING}"
        fi
        FOUND_MISSING=$(find "${MNT_POINT}" -name "${FILENAME_MISSING}" | head -1 || true)
        if [[ -f ${FOUND_MISSING} ]] && ! [[ -f "${MNT_POINT}""${DIR_NAME_MISSING}"/"${FOUND_MISSING}" ]]; then
          print_output "[*] Recover missing file ${ORANGE}${FILENAME_MISSING}${NC} in filesystem ... trying to fix this now"
          cp -n "${FOUND_MISSING}" "${MNT_POINT}""${DIR_NAME_MISSING}"/ || true
        fi
      done
    fi

    # umount filesystem:
    umount_qemu_image "${DEVICE}"
  fi
}

nvram_check() {
  local IMAGE_NAME="${1:-}"
  local MAX_THREADS_NVRAM=$((4*"$(grep -c ^processor /proc/cpuinfo || true)"))

  # mount filesystem again for network config:
  print_output "[*] Identify Qemu Image device for ${ORANGE}${LOG_PATH_MODULE}/${IMAGE_NAME}${NC}"
  DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
  if [[ "${DEVICE}" == "NA" ]]; then
    DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
  fi
  if [[ "${DEVICE}" == "NA" ]]; then
    print_output "[-] No Qemu Image device identified"
    return
  fi
  sleep 1

  print_output "[*] Device mapper created at ${ORANGE}${DEVICE}${NC}"
  print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
  mount "${DEVICE}" "${MNT_POINT}" || true

  if mount | grep -q "${MNT_POINT}"; then
    if [[ -v NVRAMS[@] ]]; then
      print_output "[*] NVRAM access detected ${ORANGE}${#NVRAMS[@]}${NC} times. Testing NVRAM access now."
      CURRENT_DIR=$(pwd)
      cd "${MNT_POINT}" || exit
      # generate a file list of the firmware
      mapfile -t NVRAM_FILE_LIST < <(find . -xdev -type f -not -path "*/firmadyne*" || true)

      if ! [[ -d "${LOG_PATH_MODULE}"/nvram ]]; then
        mkdir "${LOG_PATH_MODULE}"/nvram
      fi

      # need to check for firmadyne string in path
      for NVRAM_FILE in "${NVRAM_FILE_LIST[@]}"; do
        nvram_searcher_emulation &
        WAIT_PIDS_AE+=( "$!" )
        max_pids_protection "${MAX_THREADS_NVRAM}" "${WAIT_PIDS_AE[@]}"
      done
      wait_for_pid "${WAIT_PIDS_AE[@]}"
      cd "${CURRENT_DIR}" || exit
    fi
 
    if [[ -f "${LOG_PATH_MODULE}"/nvram/nvram_files_final ]]; then
      if [[ "$(wc -l "${LOG_PATH_MODULE}"/nvram/nvram_files_final | awk '{print $1}')" -gt 0 ]]; then
        # print_output "[*] Identified the following NVRAM files:"
        # tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/nvram/nvram_files_final

        sort -u -r -h -k2 "${LOG_PATH_MODULE}"/nvram/nvram_files_final | sort -u -k1,1 | sort -r -h -k2 | head -10 > "${MNT_POINT}"/firmadyne/nvram_files
        # store a copy in the log dir
        cp "${MNT_POINT}"/firmadyne/nvram_files "${LOG_PATH_MODULE}"/nvram/nvram_files_final_

        print_ln
        print_output "[*] Setting up ${ORANGE}nvram_files${NC} in target filesystem:"
        tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/nvram/nvram_files_final_
      fi
    fi
  fi

  # umount filesystem:
  umount_qemu_image "${DEVICE}"

}

nvram_searcher_emulation() {
  if file "${NVRAM_FILE}" | grep -q "ASCII text"; then
    local COUNT=0
    if [[ "${#NVRAMS[@]}" -gt 1000 ]]; then
      MAX_VALUES=1000
    else
      MAX_VALUES="${#NVRAMS[@]}"
    fi
    for (( j=0; j<"${MAX_VALUES}"; j++ )); do
      NVRAM_ENTRY="${NVRAMS[${j}]}"
      # check https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/inferDefault.py
      echo "${NVRAM_ENTRY}" >> "${LOG_PATH_MODULE}"/nvram/nvram_keys.tmp
      NVRAM_KEY=$(echo "${NVRAM_ENTRY}" | tr -dc '[:print:]' | tr -s '[:blank:]')
      if [[ "${NVRAM_KEY}" =~ [a-zA-Z0-9_] && "${#NVRAM_KEY}" -gt 3 ]]; then
        # print_output "[*] NVRAM access detected: $ORANGE$NVRAM_KEY$NC"
        if grep -q "${NVRAM_KEY}" "${NVRAM_FILE}" 2>/dev/null; then
          # print_output "[*] Possible NVRAM access via key $ORANGE$NVRAM_KEY$NC found in NVRAM file $ORANGE$NVRAM_FILE$NC."
          COUNT=$((COUNT + 1))
        fi
        echo "${NVRAM_KEY}" >> "${LOG_PATH_MODULE}"/nvram/nvram_keys.log
      fi
    done
    if [[ "${COUNT}" -gt 0 ]]; then
      # NVRAM_FILE=$(echo "${NVRAM_FILE}" | sed 's/^\.//')
      NVRAM_FILE="${NVRAM_FILE/\.}"
      # print_output "[*] $NVRAM_FILE $COUNT ASCII_text"
      echo "${NVRAM_FILE} ${COUNT} ASCII_text" >> "${LOG_PATH_MODULE}"/nvram/nvram_files_final
    fi
  fi
}

run_emulated_system() {
  IP_ADDRESS_="${1:-}"
  IMAGE_NAME="${2:-}"

  sub_module_title "Final system emulation for ${IP_ADDRESS_}"

  local IMAGE="${LOG_PATH_MODULE}/${IMAGE_NAME}"

  KERNEL_V=".4"
  get_kernel_version
  if [[ -n "${KERNEL_V:-}" ]]; then
    print_output "[*] Kernel ${KERNEL_V}.x detected -> Using Kernel v4.x"
    # KERNEL_V=".$KERNEL_V"
    KERNEL_V=".4"
  fi

  CONSOLE="ttyS0"
  if [[ "${ARCH_END}" == "mipsel" ]]; then
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}${KERNEL_V}"
    QEMU_BIN="qemu-system-${ARCH_END}"
    QEMU_MACHINE="malta"
  elif [[ "${ARCH_END}" == "mips64r2el" ]]; then
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}${KERNEL_V}"
    QEMU_BIN="qemu-system-${ARCH_END}"
    CPU="-cpu MIPS64R2-generic"
    QEMU_MACHINE="malta"
  elif [[ "${ARCH_END}" == "mipseb" ]]; then
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}${KERNEL_V}"
    QEMU_BIN="qemu-system-mips"
    QEMU_MACHINE="malta"
  elif [[ "${ARCH_END}" == "mips64r2eb" ]]; then
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}${KERNEL_V}"
    QEMU_BIN="qemu-system-mips64"
    CPU="-cpu MIPS64R2-generic"
    QEMU_MACHINE="malta"
  elif [[ "${ARCH_END}" == "mips64v1eb" ]]; then
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}${KERNEL_V}"
    QEMU_BIN="qemu-system-mips64"
    # CPU="-cpu MIPS64R2-generic"
    QEMU_MACHINE="malta"
  elif [[ "${ARCH_END}" == "mips64v1el" ]]; then
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}${KERNEL_V}"
    QEMU_BIN="qemu-system-mips64el"
    # CPU="-cpu MIPS64R2-generic"
    QEMU_MACHINE="malta"
  elif [[ "${ARCH_END}" == "mips64n32eb" ]]; then
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}${KERNEL_V}"
    QEMU_BIN="qemu-system-mips64"
    CPU="-cpu MIPS64R2-generic"
    QEMU_MACHINE="malta"
  elif [[ "${ARCH_END}" == "armel"* ]]; then
    KERNEL="${BINARY_DIR}/zImage.${ARCH_END}"
    QEMU_BIN="qemu-system-arm"
    QEMU_MACHINE="virt"
  elif [[ "${ARCH_END}" == "arm64el"* ]]; then
    KERNEL="${BINARY_DIR}/Image.${ARCH_END}"
    QEMU_BIN="qemu-system-aarch64"
    # CONSOLE="ttyAMA0"
    CPU="-cpu cortex-a57"
    QEMU_MACHINE="virt"
  elif [[ "${ARCH_END}" == "x86el"* ]]; then
    KERNEL="${BINARY_DIR}/bzImage.${ARCH_END}"
    QEMU_BIN="qemu-system-x86_64"
    QEMU_MACHINE="pc-i440fx-3.1"
  elif [[ "${ARCH_END}" == "nios2el" ]]; then
    # not implemented -> Future
    KERNEL="${BINARY_DIR}/vmlinux.${ARCH_END}"
    QEMU_BIN="qemu-system-nios2"
    QEMU_MACHINE="10m50-ghrd"
  else
    QEMU_BIN="NA"
  fi

  if [[ "${ARCH}" == "ARM"* ]]; then
    QEMU_DISK="-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    QEMU_PARAMS="-audiodev driver=none,id=none"
    QEMU_ROOTFS="/dev/vda1"
    NET_ID=0
    # newer kernels use virtio only
    QEMU_NETWORK="-device virtio-net-device,netdev=net${NET_ID} -netdev tap,id=net${NET_ID},ifname=${TAPDEV_0},script=no"

  elif [[ "${ARCH}" == "NIOS2" ]]; then
    QEMU_PARAMS="-monitor none"
    QEMU_NETWORK=""
    QEMU_DISK="-drive file=${IMAGE},format=raw"
  elif [[ "${ARCH}" == "MIPS" ]] || [[ "${ARCH_END}" == "x86el" ]] || [[ "${ARCH_END}" == "mips64"* ]]; then
    QEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    QEMU_PARAMS=""
    QEMU_ROOTFS="/dev/sda1"
    QEMU_NETWORK=""

    if [[ -n "${ETH_NUM}" ]]; then
      # if we found an eth interface we use this
      NET_NUM="${ETH_NUM}"
    elif [[ -n "${BR_NUM}" ]]; then
      # if we found no eth interface but a br interface we use this
      NET_NUM="${BR_NUM}"
    else
      # fallback - we connect id 0
      NET_NUM=0
    fi

    # 4 Interfaces -> 0-3
    for NET_ID in {0..3}; do
      QEMU_NETWORK="${QEMU_NETWORK} -device e1000,netdev=net${NET_ID}"
      if [[ "${NET_ID}" == "${NET_NUM}" ]];then
        # if MATCH in IPS_INT -> connect this interface to host
        print_output "[*] Connect interface: ${ORANGE}${NET_ID}${NC} to host"
        QEMU_NETWORK="${QEMU_NETWORK} -netdev tap,id=net${NET_ID},ifname=${TAPDEV_0},script=no"
      else
        print_output "[*] Create socket placeholder interface: ${ORANGE}${NET_ID}${NC}"
        # place a socket connection placeholder:
        QEMU_NETWORK="${QEMU_NETWORK} -netdev socket,id=net${NET_ID},listen=:200${NET_ID}"
      fi
    done
  fi

  if [[ "${QEMU_BIN}" != "NA" ]]; then
    run_qemu_final_emulation &
  else
    print_output "[-] No firmware emulation ${ORANGE}${ARCH}${NC} / ${ORANGE}${IMAGE_NAME}${NC} possible"
  fi
}

run_qemu_final_emulation() {
  check_qemu_instance_l10
  print_output "[*] Qemu parameters used in run mode:"
  print_output "$(indent "MACHINE: ${ORANGE}${QEMU_MACHINE}${NC}")"
  print_output "$(indent "KERNEL: ${ORANGE}${KERNEL}${NC}")"
  print_output "$(indent "DISK: ${ORANGE}${QEMU_DISK}${NC}")"
  print_output "$(indent "KINIT: ${ORANGE}${KINIT}${NC}")"
  print_output "$(indent "ROOT_DEV: ${ORANGE}${QEMU_ROOTFS}${NC}")"
  print_output "$(indent "QEMU: ${ORANGE}${QEMU_BIN}${NC}")"
  print_output "$(indent "NETWORK: ${ORANGE}${QEMU_NETWORK}${NC}")"
  print_output "$(indent "Init file ${ORANGE}${INIT_FILE}${NC}")"
  print_output "$(indent "Console interface ${ORANGE}${CONSOLE}${NC}")"
  print_ln
  print_output "[*] Starting firmware emulation ${ORANGE}${QEMU_BIN} / ${ARCH_END} / ${IMAGE_NAME} / ${IP_ADDRESS_}${NC} ... use Ctrl-a + x to exit"
  print_ln

  write_script_exec "echo -e \"[*] Starting firmware emulation ${ORANGE}${QEMU_BIN} / ${ARCH_END} / ${IMAGE_NAME} / ${IP_ADDRESS_}${NC} ... use Ctrl-a + x to exit\n\"" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "echo -e \"[*] For emulation state please monitor the ${ORANGE}qemu.serial.log${NC} file\n\"" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "echo -e \"[*] For shell access check localhost port ${ORANGE}4321${NC} via telnet\n\"" "${ARCHIVE_PATH}"/run.sh 0
 
  write_script_exec "${QEMU_BIN} -m 2048 -M ${QEMU_MACHINE} ${CPU} -kernel ${KERNEL} ${QEMU_DISK} -append \"root=${QEMU_ROOTFS} console=${CONSOLE} nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${KINIT} rw debug ignore_loglevel print-fatal-signals=1 FIRMAE_NET=${FIRMAE_NET} FIRMAE_NVRAM=${FIRMAE_NVRAM} FIRMAE_KERNEL=${FIRMAE_KERNEL} FIRMAE_ETC=${FIRMAE_ETC} user_debug=0 firmadyne.syscall=1\" -nographic ${QEMU_NETWORK} ${QEMU_PARAMS} -serial file:${LOG_PATH_MODULE}/qemu.final.serial.log -serial telnet:localhost:4321,server,nowait -serial unix:/tmp/qemu.${IMAGE_NAME}.S1,server,nowait -monitor unix:/tmp/qemu.${IMAGE_NAME},server,nowait ; pkill -9 -f tail.*-F.*\"${LOG_PATH_MODULE}\"" "${ARCHIVE_PATH}"/run.sh 1
}

check_online_stat() {
  local IP_ADDRESS_="${1:-}"
  local NMAP_LOG="${2:-}"
  local PING_CNT=0
  local SYS_ONLINE=0
  local TCP_SERV_NETSTAT_ARR=()
  local UDP_SERV_NETSTAT_ARR=()

  if [[ "${QEMU_BIN}" == "NA" ]]; then
    return
  fi

  # we write the results to a tmp file. This is needed to only have the results of the current emulation round
  # for further processing available
  while [[ "${PING_CNT}" -lt 24 && "${SYS_ONLINE}" -eq 0 ]]; do
    if ping -c 1 "${IP_ADDRESS_}" &> /dev/null; then
      print_output "[+] Host with ${ORANGE}${IP_ADDRESS_}${GREEN} is reachable via ICMP."
      ping -c 1 "${IP_ADDRESS_}" | tee -a "${LOG_FILE}" || true
      print_ln
      echo -e "${GREEN}[+] Host with ${ORANGE}${IP_ADDRESS_}${GREEN} is reachable via ICMP." >> "${TMP_DIR}"/online_stats.tmp
      SYS_ONLINE=1
    fi

    if [[ "$(hping3 -n -c 1 "${IP_ADDRESS_}" 2>/dev/null | grep -c "^len=")" -gt 0 ]]; then
      print_output "[+] Host with ${ORANGE}${IP_ADDRESS_}${GREEN} is reachable on TCP port 0 via hping."
      hping3 -n -c 1 "${IP_ADDRESS_}" | tee -a "${LOG_FILE}" || true
      print_ln
      if [[ "${SYS_ONLINE}" -ne 1 ]]; then
        if ping -c 1 "${IP_ADDRESS_}" &> /dev/null; then
          print_output "[+] Host with ${ORANGE}${IP_ADDRESS_}${GREEN} is reachable via ICMP."
          ping -c 1 "${IP_ADDRESS_}" | tee -a "${LOG_FILE}"
          print_ln
          echo -e "${GREEN}[+] Host with ${ORANGE}${IP_ADDRESS_}${GREEN} is reachable via ICMP." >> "${TMP_DIR}"/online_stats.tmp
        fi
      fi
      print_ln
      echo -e "${GREEN}[+] Host with ${ORANGE}${IP_ADDRESS_}${GREEN} is reachable on TCP port 0 via hping." >> "${TMP_DIR}"/online_stats.tmp
      SYS_ONLINE=1
    fi

    if [[ "${SYS_ONLINE}" -eq 0 ]]; then
      print_output "[*] Host with ${ORANGE}${IP_ADDRESS_}${NC} is not reachable."
      SYS_ONLINE=0
      sleep 5
    fi
    PING_CNT=("${PING_CNT}"+1)
  done

  if [[ "${SYS_ONLINE}" -eq 1 ]]; then
    print_output "[*] Give the system another 130 seconds to ensure the boot process is finished.\n" "no_log"
    sleep 130
    print_output "[*] Nmap portscan for ${ORANGE}${IP_ADDRESS_}${NC}"
    write_link "${ARCHIVE_PATH}"/"${NMAP_LOG}"
    print_ln
    ping -c 1 "${IP_ADDRESS_}" | tee -a "${LOG_FILE}" || true
    print_ln
    nmap -Pn -n -A -sSV --host-timeout 30m -oA "${ARCHIVE_PATH}"/"$(basename "${NMAP_LOG}")" "${IP_ADDRESS_}" | tee -a "${ARCHIVE_PATH}"/"${NMAP_LOG}" "${LOG_FILE}" || true

    mapfile -t TCP_SERV_NETSTAT_ARR < <(grep -a "^tcp.*LISTEN" "${LOG_PATH_MODULE}"/qemu*.log | grep -v "127.0.0.1" | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u || true)
    mapfile -t UDP_SERV_NETSTAT_ARR < <(grep -a "^udp.*" "${LOG_PATH_MODULE}"/qemu*.log | grep -v "127.0.0.1" | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u || true)

    if [[ "${#SERVICES_STARTUP[@]}" -gt 0 ]] || [[ -v TCP_SERV_NETSTAT_ARR[@] ]] || [[ -v UDP_SERV_NETSTAT_ARR[@] ]]; then
      local UDP_SERV_NETSTAT=""
      local UDP_SERV_STARTUP=""
      local UDP_SERV=""
      local TCP_SERV_NETSTAT=""
      local TCP_SERV_STARTUP=""
      local TCP_SERV=""
      local TCP_SERV_ARR=()
      local UDP_SERV_ARR=()
      local PORTS_TO_SCAN=""

      # write all services into a one liner for output:
      print_ln
      if [[ -v TCP_SERVICES_STARTUP[@] ]]; then
        printf -v TCP_SERV "%s " "${TCP_SERVICES_STARTUP[@]}"
        TCP_SERV_STARTUP=${TCP_SERV//\ /,}
        print_output "[*] TCP Services detected via startup: ${ORANGE}${TCP_SERV_STARTUP}${NC}"
      fi
      if [[ -v UDP_SERVICES_STARTUP[@] ]]; then
        printf -v UDP_SERV "%s " "${UDP_SERVICES_STARTUP[@]}"
        UDP_SERV_STARTUP=${UDP_SERV//\ /,}
        print_output "[*] UDP Services detected via startup: ${ORANGE}${UDP_SERV_STARTUP}${NC}"
      fi

      if [[ "${#TCP_SERV_NETSTAT_ARR[@]}" -gt 0 ]]; then
        printf -v TCP_SERV "%s " "${TCP_SERV_NETSTAT_ARR[@]}"
        TCP_SERV_NETSTAT=${TCP_SERV//\ /,}
        print_output "[*] TCP Services detected via netstat: ${ORANGE}${TCP_SERV_NETSTAT}${NC}"
      fi
      if [[ "${#UDP_SERV_NETSTAT_ARR[@]}" -gt 0 ]]; then
        printf -v UDP_SERV "%s " "${UDP_SERV_NETSTAT_ARR[@]}"
        UDP_SERV_NETSTAT=${UDP_SERV//\ /,}
        print_output "[*] UDP Services detected via netstat: ${ORANGE}${UDP_SERV_NETSTAT}${NC}"
      fi
      print_ln

      # work with this:
      TCP_SERV_ARR=( "${TCP_SERVICES_STARTUP[@]}" "${TCP_SERV_NETSTAT_ARR[@]}" )
      UDP_SERV_ARR=( "${UDP_SERVICES_STARTUP[@]}" "${UDP_SERV_NETSTAT_ARR[@]}" )
      eval "TCP_SERV_ARR=($(for i in "${TCP_SERV_ARR[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
      eval "UDP_SERV_ARR=($(for i in "${UDP_SERV_ARR[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
      if [[ -v TCP_SERV_ARR[@] ]]; then
        printf -v TCP_SERV "%s " "${TCP_SERV_ARR[@]}"
        TCP_SERV=${TCP_SERV//\ /,}
        # print_output "[*] TCP Services detected: $ORANGE$TCP_SERV$NC"
      fi
      if [[ -v UDP_SERV_ARR[@] ]]; then
        printf -v UDP_SERV "%s " "${UDP_SERV_ARR[@]}"
        UDP_SERV=${UDP_SERV//\ /,}
        # print_output "[*] UDP Services detected: $ORANGE$UDP_SERV$NC"
      fi

      UDP_SERV="U:""${UDP_SERV}"
      TCP_SERV="T:""${TCP_SERV}"
      TCP_SERV="${TCP_SERV%,}"
      UDP_SERV="${UDP_SERV%,}"
      
      local PORTS_TO_SCAN=""
      if [[ "${TCP_SERV}" =~ ^T:[0-9].* ]]; then
        print_output "[*] Detected TCP services ${ORANGE}${TCP_SERV}${NC}"
        PORTS_TO_SCAN="${TCP_SERV}"
      fi
      if [[ "${UDP_SERV}" =~ ^U:[0-9].* ]]; then
        print_output "[*] Detected UDP services ${ORANGE}${UDP_SERV}${NC}"
        if [[ "${PORTS_TO_SCAN}" =~ ^T:[0-9].* ]]; then
          PORTS_TO_SCAN="${PORTS_TO_SCAN},${UDP_SERV}"
        else
          PORTS_TO_SCAN="${UDP_SERV}"
        fi
      fi

      if [[ "${TCP_SERV}" =~ ^T:[0-9].* ]] || [[ "${UDP_SERV}" =~ ^U:[0-9].* ]]; then
        print_ln
        print_output "[*] Nmap portscan for detected services (${ORANGE}${PORTS_TO_SCAN}${NC}) started during system init on ${ORANGE}${IP_ADDRESS_}${NC}"
        write_link "${ARCHIVE_PATH}"/"${NMAP_LOG}"
        print_ln
        nmap -Pn -n -sSUV --host-timeout 30m -p "${PORTS_TO_SCAN}" -oA "${ARCHIVE_PATH}"/nmap_emba_"${IPS_INT_VLAN_CFG_mod}"_dedicated "${IP_ADDRESS_}" | tee -a "${ARCHIVE_PATH}"/"${NMAP_LOG}" "${LOG_FILE}" || true
      fi
    fi
  fi

  stopping_emulation_process "${IMAGE_NAME}"
  # if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
  #  reset_network_emulation 1
  # else
  #  reset_network_emulation 2
  # fi
  cleanup_emulator "${IMAGE_NAME}"

  color_qemu_log "${LOG_PATH_MODULE}/qemu.final.serial.log"

  pkill -9 -f "tail -F ${LOG_PATH_MODULE}/qemu.final.serial.log" || true &>/dev/null
}

stopping_emulation_process() {
  local IMAGE_NAME_="${1:-}"
  print_output "[*] Stopping emulation process" "no_log"
  pkill -9 -f "qemu-system-.*${IMAGE_NAME_}.*" &>/dev/null || true
  sleep 1
}

create_emulation_archive() {
  ARCHIVE_PATH="${1:-}"
  sub_module_title "Archive to re-run emulated environment"
  print_output "With the following archive it is possible to rebuild the created emulation environment fully automated."

  cp "${KERNEL}" "${ARCHIVE_PATH}" || true
  cp "${IMAGE}" "${ARCHIVE_PATH}" || true
  if [[ -f "${LOG_PATH_MODULE}"/"${NMAP_LOG}" ]]; then
    mv "${LOG_PATH_MODULE}"/"${NMAP_LOG}" "${ARCHIVE_PATH}" || true
    mv "${LOG_PATH_MODULE}"/nmap_emba_"${IPS_INT_VLAN_CFG_mod}"* "${ARCHIVE_PATH}" || true
  fi
  echo "${IPS_INT_VLAN_CFG_mod}" >> "${ARCHIVE_PATH}"/emulation_config.txt || true
  cat "${LOG_DIR}"/emulator_online_results.log >> "${ARCHIVE_PATH}"/emulation_config.txt || true

  if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
    chmod +x "${ARCHIVE_PATH}"/run.sh
    sed -i 's/-serial\ file:.*\/l10_system_emulation\/qemu\.final\.serial\.log/-serial\ file:\.\/qemu\.serial\.log/g' "${ARCHIVE_PATH}"/run.sh

    # create archive
    ARCH_NAME="$(basename "${ARCHIVE_PATH}")".tar.gz
    tar -czvf "${LOG_PATH_MODULE}"/"${ARCH_NAME}" "${ARCHIVE_PATH}"
    if [[ -f "${LOG_PATH_MODULE}"/"${ARCH_NAME}" ]]; then
      print_ln
      print_output "[*] Qemu emulation archive created in log directory: ${ORANGE}${ARCH_NAME}${NC}" "" "${LOG_PATH_MODULE}/${ARCH_NAME}"
      print_ln
    fi
  else
    print_output "[-] No run script created ..."
  fi
}

# EXECUTE: 0 -> just write script
# EXECUTE: 1 -> execute and write script
# EXECUTE: 2 -> just execute
reset_network_emulation() {
  EXECUTE_="${1:0}"

  if ! [[ -v IMAGE_NAME ]] || ! [[ -v ARCHIVE_PATH ]]; then
    return
  fi

  # Todo: handle network shutdown also on restarted tests
  if [[ "${RESTART}" -ne 0 ]]; then
    return
  fi

  if [[ "${EXECUTE_}" -ne 0 ]]; then
    print_output "[*] Stopping Qemu emulation ..." "no_log"
    pkill -9 -f "qemu-system-.*${IMAGE_NAME}.*" || true &>/dev/null
  fi

  if [[ "${EXECUTE_}" -eq 1 ]] && ! grep -q "Deleting route" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    write_script_exec "echo -e \"Deleting route ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi
  if [[ -v HOSTNETDEV_0 ]] && ! grep -q "ip route flush dev" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "[*] Deleting route..." "no_log"
    write_script_exec "ip route flush dev ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh "${EXECUTE_}"
  fi

  if [[ "${EXECUTE_}" -eq 1 ]] && ! grep -q "Bringing down TAP device" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "[*] Bringing down TAP device..." "no_log"
    write_script_exec "echo -e \"Bringing down TAP device ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi
  if [[ "${EXECUTE_}" -lt 2 ]] && ! grep -q "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    EXECUTE_tmp=1
  else
    EXECUTE_tmp="${EXECUTE_}"
  fi
  write_script_exec "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh "${EXECUTE_tmp}"

  if [[ "${EXECUTE_}" -eq 1 ]] && ! grep -q "Removing VLAN" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "Removing VLAN..." "no_log"
    write_script_exec "echo -e \"Removing VLAN ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi

  if [[ "${EXECUTE_}" -lt 2 ]] && ! grep -q "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    EXECUTE_tmp=1
  else
    EXECUTE_tmp="${EXECUTE_}"
  fi
  write_script_exec "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh "${EXECUTE_tmp}"

  if [[ "${EXECUTE_}" -eq 1 ]] && ! grep -q "Deleting TAP device" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "Deleting TAP device ${TAPDEV_0}..." "no_log"
    write_script_exec "echo -e \"Deleting TAP device ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi

  if [[ "${EXECUTE_}" -lt 2 ]] && ! grep -q "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    EXECUTE_tmp=1
  else
    EXECUTE_tmp="${EXECUTE_}"
  fi
  write_script_exec "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh "${EXECUTE_tmp}"
}

write_script_exec() {
  COMMAND="${1:-}"
  # SCRIPT_WRITE: File to write
  SCRIPT_WRITE="${2:-}"
  # EXECUTE: 0 -> just write script
  # EXECUTE: 1 -> execute and write script
  # EXECUTE: 2 -> just execute
  EXECUTE="${3:0}"

  if [[ "${EXECUTE}" -ne 0 ]];then
    eval "${COMMAND}" || true &
    PID="$!"
    disown "${PID}" 2> /dev/null || true
  fi

  if [[ "${EXECUTE}" -ne 2 ]];then
    if ! [[ -f "${SCRIPT_WRITE}" ]]; then
      # just in case we have our script not already there we set it up now
      echo "#!/bin/bash -p" > "${SCRIPT_WRITE}"
    fi

    # for the final script we need to adjust the paths:
    if echo "${COMMAND}" | grep -q qemu-system-; then
      # fix path for kernel: /external/firmae/binaries/vmlinux.mipsel.4 -> ./vmlinux.mipsel.4
      # fix path for kernel: /external/EMBA_Live_bins/vmlinux.mipsel.4 -> ./vmlinux.mipsel.4
      #shellcheck disable=SC2001
      COMMAND=$(echo "${COMMAND}" | sed 's#-kernel\ .*\/EMBA_Live_bins\/#-kernel\ .\/#g')
      #shellcheck disable=SC2001
      COMMAND=$(echo "${COMMAND}" | sed "s#${IMAGE:-}#\.\/${IMAGE_NAME:-}#g")
      #shellcheck disable=SC2001
      COMMAND=$(echo "${COMMAND}" | sed "s#\"${LOG_PATH_MODULE:-}\"#\.#g")
    fi

    echo "${COMMAND}" >> "${SCRIPT_WRITE}"
  fi
}

get_binary() {
  echo "${BINARY_DIR}/${1}.${2}"
}

add_partition_emulation() {
  local IMAGE_PATH
  local DEV_PATH="NA"
  local FOUND=false
  local CNT=0

  losetup -Pf "${1}"
  while (! "${FOUND}"); do
    sleep 1
    ((CNT+=1))
    local LOSETUP_OUT=()
    mapfile -t LOSETUP_OUT < <(losetup | grep -v "BACK-FILE")
    for LINE in "${LOSETUP_OUT[@]}"; do
      IMAGE_PATH=$(echo "${LINE}" | awk '{print $6}')
      if [[ "${IMAGE_PATH}" == "${1}" ]]; then
        DEV_PATH=$(echo "${LINE}" | awk '{print $1}')p1
        if [[ -b "${DEV_PATH}" ]]; then
          FOUND=true
        fi
      fi
    done
    if [[ "${CNT}" -gt 600 ]]; then
      # get an exit if nothing happens
      break
    fi
  done

  local CNT=0
  while (! find "${DEV_PATH}" -ls | grep -q "disk"); do
    sleep 1
    ((CNT+=1))
    if [[ "${CNT}" -gt 600 ]]; then
      # get an exit if nothing happens
      break
    fi
  done
  echo "${DEV_PATH}"
}

get_kernel_version() {
  if [[ -f "${LOG_DIR}"/"${S25_LOG}" ]]; then
    mapfile -t KERNELV < <(grep "Statistics:" "${LOG_DIR}"/"${S25_LOG}" | cut -d: -f2 | sort -u || true)
    if [[ -v KERNELV[@] ]]; then
      # if we have found a kernel it is a Linux system:$
      for KV in "${KERNELV[@]}"; do
        if [[ "${KV}" == "2"* ]]; then
          KERNEL_V=2
          break
        elif [[ "${KV}" == "4"* ]]; then
          KERNEL_V=4
          break
        else
          # just to have some fallback solution
          KERNEL_V=4
          break
        fi
      done
    fi
  else
    # just to have some fallback solution
    KERNEL_V=4
  fi
}

set_network_config() {
  local IP_ADDRESS_="${1:-}"
  local NETWORK_MODE="${2:-}"
  local NETWORK_DEVICE="${3:-}"
  local ETH_INT="${4:-}"

  echo "${NETWORK_MODE}" > "${MNT_POINT}/firmadyne/network_type"
  echo "${NETWORK_DEVICE}" > "${MNT_POINT}/firmadyne/net_bridge"
  echo "${ETH_INT}" > "${MNT_POINT}/firmadyne/net_interface"
  if [[ -z "${IP_ADDRESS_}" ]]; then
    IP_ADDRESS_="192.168.0.1"
  fi
  echo "${IP_ADDRESS_}" > "${MNT_POINT}/firmadyne/ip_default"
}

write_results() {
  if [[ "${IN_DOCKER}" -eq 1 ]] && [[ -f "${TMP_DIR}"/fw_name.log ]]; then
    local FIRMWARE_PATH_orig
    FIRMWARE_PATH_orig="$(cat "${TMP_DIR}"/fw_name.log)"
  fi

  local ARCHIVE_PATH_="${1:-}"
  local R_PATH_="${2:-}"
  local R_PATH_mod=""
  # R_PATH_mod="$(echo "${R_PATH_}" | sed "s#$LOG_DIR##g")"
  R_PATH_mod="${R_PATH_/${LOG_DIR}/}"
  local TCP_SERV_CNT=0
  if [[ -f "${ARCHIVE_PATH}"/"${NMAP_LOG}" ]]; then
    TCP_SERV_CNT="$(grep "udp.*open\ \|tcp.*open\ " "${ARCHIVE_PATH}"/"${NMAP_LOG}" 2>/dev/null | awk '{print $1}' | sort -u | wc -l || true)"
  fi
  [[ "${TCP_SERV_CNT}" -gt 0 ]] && TCP="ok"
  ARCHIVE_PATH_="$(echo "${ARCHIVE_PATH_}" | rev | cut -d '/' -f1 | rev)"
  if ! [[ -f "${LOG_DIR}"/emulator_online_results.log ]]; then
    echo "FIRMWARE_PATH;RESULT_SOURCE;Booted state;ICMP state;TCP-0 state;TCP state;online services;IP address;Network mode (NETWORK_DEVICE/ETH_INT/INIT_FILE);ARCHIVE_PATH_;R_PATH" > "${LOG_DIR}"/emulator_online_results.log
  fi
  echo "${FIRMWARE_PATH_orig};${RESULT_SOURCE};Booted ${BOOTED};ICMP ${ICMP};TCP-0 ${TCP_0};TCP ${TCP};${TCP_SERV_CNT};IP address: ${IP_ADDRESS_};Network mode: ${NETWORK_MODE} (${NETWORK_DEVICE}/${ETH_INT}/${INIT_FILE});${ARCHIVE_PATH_};${R_PATH_mod}" >> "${LOG_DIR}"/emulator_online_results.log
  print_bar ""
}

set_firmae_arbitration() {
  FIRMAE_STATE="${1:-true}"
  # FirmAE arbitration - enable all mechanisms
  export FIRMAE_BOOT="${FIRMAE_STATE}"
  export FIRMAE_NET="${FIRMAE_STATE}"
  export FIRMAE_NVRAM="${FIRMAE_STATE}"
  export FIRMAE_KERNEL="${FIRMAE_STATE}"
  export FIRMAE_ETC="${FIRMAE_STATE}"
}

color_qemu_log() {
  local QEMU_LOG_FILE_="${1:-}"
  if ! [[ -f "${QEMU_LOG_FILE_:-}" ]]; then
    return
  fi

  # GREEN: keywords for network identification:
  sed -i -r "s/.*br_add_if.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*br_dev_ioctl.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*__inet_insert_ifa.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*ioctl_SIOCSIFHWADDR.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*register_vlan_dev.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*\[NVRAM\]\ .*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*inet_bind.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*adding VLAN [0-9] to HW filter on device eth[0-9].*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"

  # Green: other interesting areas:
  sed -i -r "s/.*Kernel\ command\ line:\ .*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*Starting\ services\ in\ emulated\ environment.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*Network configuration - ACTION.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*starting\ network\ configuration.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*Current\ network\ configuration.*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*Netstat\ output\ .*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"
  sed -i -r "s/.*Starting\ .*\ service\ .*/\x1b[32m&\x1b[0m/" "${QEMU_LOG_FILE_}"

  # RED:
  sed -i -r "s/.*Kernel\ panic\ -\ .*/\x1b[31m&\x1b[0m/" "${QEMU_LOG_FILE_}"
}

#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2015 - 2016, Daming Dominic Chen
#
# EMBA comes with ABSOLUTELY NO WARRANTY.
#
# This module is licensed under MIT
# See LICENSE file for usage of this software.
# SPDX-License-Identifier: MIT
#
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE
#
# Author(s): Michael Messner

# Description:  Builds and emulates Linux firmware - this module is based on the great work of firmadyne and firmAE
#               Check out the original firmadyne project at https://github.com/firmadyne
#               Check out the original FirmAE project at https://github.com/pr0v3rbs/FirmAE
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
# Warning:      This module changes your network configuration and it could happen that your system looses
#               network connectivity.
#
# shellcheck disable=SC2153

L10_system_emulation() {
  module_log_init "${FUNCNAME[0]}"
  module_title "System emulation of Linux based embedded devices."

  # enable L10_DEBUG_MODE in scan profile or default config for further debugging capabilities:
  # * create_emulation_archive for all attempts
  # * do not stop after 2 detected network services
  # * enable experimental tests

  export SYS_ONLINE=0
  export TCP=""
  local lARCH_END=""
  local lMODULE_END=0
  local lUNSUPPORTED_ARCH=0
  export STATE_CHECK_MECHANISM="PING"

  if [[ "${FULL_EMULATION}" -eq 1 && "${RTOS}" -eq 0 ]]; then
    pre_module_reporter "${FUNCNAME[0]}"
    export MODULE_SUB_PATH="${MOD_DIR}"/"${FUNCNAME[0]}"

    local lIMAGE_DIR=""
    export IMAGE_NAME=""
    export ARCHIVE_PATH=""
    export HOSTNETDEV_ARR=()
    local lEMULATION_ENTRY=""
    export BINARY_DIR="${EXT_DIR}/EMBA_Live_bins"
    # lFIRMWARE_PATH_orig="$(abs_path "${FIRMWARE_PATH_BAK}")"
    LOG_PATH_MODULE=$(abs_path "${LOG_PATH_MODULE}")
    local lR_PATH_CNT=1
    local lIP_ADDRESS=""
    export R_PATH=""
    export MIN_TCP_SERV=2
    ### export IP_ADDRESS_=""

    # if we have a supported arch we move on with out emulation attempt
    if [[ "${ARCH}" == "MIPS"* || "${ARCH}" == "ARM"* || "${ARCH}" == "x86" ]]; then

      check_bmc_supermicro

      # WARNING: false was never tested ;)
      # Could be interesting for future extensions
      set_firmae_arbitration "true"

      # just to ensure nothing has already put a run.sh into our log
      find "${LOG_PATH_MODULE}" -name "run.sh" --delete 2>/dev/null || true

      # handling restarted scans with old emulation processes:
      if [[ -f "${L10_SYS_EMU_RESULTS}" ]] && grep -q "L10_system_emulation finished" "${LOG_DIR}"/emba.log; then
        print_ln
        print_output "[*] Found finished emulation process - trying to recover old emulation process"

        lEMULATION_ENTRY="$(grep "TCP ok" "${L10_SYS_EMU_RESULTS}" | sort -k 7 -t ';' | tail -1)"
        lIP_ADDRESS=$(grep "TCP ok" "${L10_SYS_EMU_RESULTS}" | sort -k 7 -t ';' | tail -1 | cut -d\; -f8 | awk '{print $3}')
        lIMAGE_DIR="$(grep "TCP ok" "${L10_SYS_EMU_RESULTS}" | sort -k 7 -t ';' | tail -1 | cut -d\; -f10)"
        ARCHIVE_PATH="${OLD_LOG_DIR}""/""${lIMAGE_DIR}"

        print_output "[*] Recovered IP address: ${ORANGE}${lIP_ADDRESS}${NC}"
        print_output "[*] Recovered IMAGE_DIR: ${ORANGE}${lIMAGE_DIR}${NC}"
        print_output "[*] Recovered ARCHIVE_PATH: ${ORANGE}${ARCHIVE_PATH}${NC}"

        if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
          IMAGE_NAME="$(tr ' ' '\n' < "${ARCHIVE_PATH}"/run.sh | grep -o "file=.*" | cut -d '/' -f2)"
          print_output "[*] Identified IMAGE_NAME: ${ORANGE}${IMAGE_NAME}${NC}" "no_log"
          print_output "[+] Startup script (run.sh) found in old logs ... restarting emulation process now"
          mapfile -t HOSTNETDEV_ARR < <(grep "ip link set.*up" "${ARCHIVE_PATH}"/run.sh | awk '{print $4}' | sort -u)

          if [[ "${lEMULATION_ENTRY}" == *"ICMP not ok"* ]]; then
            print_output "[*] Testing system recovery with hping instead of ping" "no_log"
            STATE_CHECK_MECHANISM="HPING"
          fi
          # we should get TCP="ok" and SYS_ONLINE=1 back
          if ! restart_emulation "${lIP_ADDRESS}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
            print_output "[-] System recovery went wrong. No further analysis possible"
          fi
        else
          print_output "[-] No archive path found in old logs ... restarting emulation process not possible"
        fi
      fi

      # this is our main emulation area:
      if [[ "${SYS_ONLINE}" -ne 1 ]] && [[ "${TCP}" != "ok" ]]; then
        # ROOT_PATH array is exported from the pre-checking phase
        # shellcheck disable=SC2153
        for R_PATH in "${ROOT_PATH[@]}" ; do
          print_output "[*] Testing root path (${ORANGE}${lR_PATH_CNT}${NC}/${ORANGE}${#ROOT_PATH[@]}${NC}): ${ORANGE}${R_PATH}${NC}"
          if grep -q "P55_unblob_extractor nothing reported" "${P55_LOG}" 2>/dev/null; then
            if ! grep -q "P60_deep_extractor nothing reported" "${P60_LOG}" 2>/dev/null; then
              [[ -f "${P60_LOG}" ]] && write_link "p60"
            fi
          else
            [[ -f "${P55_LOG}" ]] && write_link "p55"
          fi

          if [[ -n "${D_END}" ]]; then
            export TAPDEV_0="tap0_0"
            local lARCH_END=""

            lARCH_END="${ARCH,,}"
            lARCH_END+="${D_END,,}"

            # default is ARM_SF -> we only need to check if it is HF
            # The information is based on the results of architecture_check()
            if [[ -n "${ARM_HF}" ]] && [[ "${ARM_HF}" -gt "${ARM_SF:-0}" ]]; then
              print_output "[*] ARM hardware floating detected"
              lARCH_END+="hf"
            fi

            if [[ "${lARCH_END}" == "armbe"* ]] || [[ "${lARCH_END}" == "mips64r2"* ]] || [[ "${lARCH_END}" == "mips64_3"* ]]; then
              print_output "[-] Found NOT supported architecture ${ORANGE}${lARCH_END}${NC}"
              [[ -f "${P99_LOG}" ]] && write_link "p99"
              print_output "[-] Please open a new issue here: https://github.com/e-m-b-a/emba/issues"
              lUNSUPPORTED_ARCH=1
              return
            fi

            # just in case we remove the return in the unsupported arch checker for testing:
            if [[ "${lUNSUPPORTED_ARCH}" -ne 1 ]]; then
              print_output "[*] Found supported architecture ${ORANGE}${lARCH_END}${NC}"
              write_link "p99"
            fi

            pre_cleanup_emulator

            main_emulation "${R_PATH}" "${lARCH_END}"

            if [[ -d "${MNT_POINT}" ]]; then
              rm -r "${MNT_POINT}" || true
            fi

            if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
              # do not test other root paths if we are already online (some ports are available)
              if [[ "${L10_DEBUG_MODE}" -eq 1 ]]; then
                print_output "[!] Debug mode: We do not stop here ..."
              else
                break
              fi
            fi
          else
            print_output "[!] No supported architecture detected"
          fi
          ((lR_PATH_CNT+=1))
        done
        print_system_emulation_results
      fi
      lMODULE_END=1
    else
      print_output "[!] No supported architecture found.\\n"
      print_output "[!] Curently supported: ${ORANGE}ARM${NC}, ${ORANGE}MIPS${NC} and ${ORANGE}x86${NC}.\\n"
      lMODULE_END=0
    fi
  fi

  if [[ "${lMODULE_END}" -ne 0 ]] && [[ -f "${L10_SYS_EMU_RESULTS}" ]]; then
    if [[ $(grep -c "TCP ok" "${L10_SYS_EMU_RESULTS}" || true) -gt 0 ]]; then
      print_ln
      print_output "[+] Identified the following system emulation results (with running network services):"
      export HOSTNETDEV_ARR=()
      local lIMAGE_DIR=""
      local lSYS_EMUL_POS_ENTRY=""
      lSYS_EMUL_POS_ENTRY="$(grep "TCP ok" "${L10_SYS_EMU_RESULTS}" | sort -t ';' -k7 -n -r | head -1 || true)"
      print_output "$(indent "$(orange "${lSYS_EMUL_POS_ENTRY}")")"

      lIP_ADDRESS=$(echo "${lSYS_EMUL_POS_ENTRY}" | grep "TCP ok" | sort -k 7 -t ';' | tail -1 | cut -d\; -f8 | awk '{print $3}')
      lIMAGE_DIR="$(echo "${lSYS_EMUL_POS_ENTRY}" | grep "TCP ok" | sort -k 7 -t ';' | tail -1 | cut -d\; -f10)"
      ARCHIVE_PATH="${LOG_PATH_MODULE}""/""${lIMAGE_DIR}"

      print_ln
      print_output "[*] Identified IP address: ${ORANGE}${lIP_ADDRESS}${NC}" "no_log"
      print_output "[*] Identified IMAGE_DIR: ${ORANGE}${lIMAGE_DIR}${NC}" "no_log"
      print_output "[*] Identified ARCHIVE_PATH: ${ORANGE}${ARCHIVE_PATH}${NC}" "no_log"

      if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
        IMAGE_NAME="$(tr ' ' '\n' < "${ARCHIVE_PATH}"/run.sh | grep -o "file=.*" | cut -d '/' -f2)"
        print_output "[*] Identified IMAGE_NAME: ${ORANGE}${IMAGE_NAME}${NC}" "no_log"
        print_output "[+] Identified emulation startup script (run.sh) in ARCHIVE_PATH ... starting emulation process for further analysis" "no_log"
        print_ln
        mapfile -t HOSTNETDEV_ARR < <(grep "ip link set.*up" "${ARCHIVE_PATH}"/run.sh | awk '{print $4}' | sort -u)
        if [[ "${lSYS_EMUL_POS_ENTRY}" == *"ICMP not ok"* ]]; then
          print_output "[*] Testing system recovery with hping instead of ping" "no_log"
          STATE_CHECK_MECHANISM="HPING"
        fi
        # we should get TCP="ok" and SYS_ONLINE=1 back
        if ! restart_emulation "${lIP_ADDRESS}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System recovery went wrong. No further analysis possible"
        fi
        export IP_ADDRESS_="${lIP_ADDRESS}"
      else
        print_output "[-] ${ORANGE}WARNING:${NC} No archive path found in logs ... restarting emulation process for further analysis not possible" "no_log"
      fi
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${lMODULE_END}"
}

check_bmc_supermicro() {
  if [[ -f "${S06_CSV_LOG}" ]]; then
    if grep -q "supermicro:bmc" "${S06_CSV_LOG}"; then
      print_output "[-] WARNING: Supermicro firmware found - Specific qemu emulation not supported"
    fi
  fi
}

print_system_emulation_results() {
  if [[ -f "${L10_SYS_EMU_RESULTS}" ]]; then
    sub_module_title "System emulation results"
    print_output "EMBA was able to identify the following system emulation results:"
    print_ln

    local lEMU_RES=""

    while read -r lEMU_RES; do
      lEMU_RES=$(echo "${lEMU_RES}" | cut -d\; -f2-)
      if [[ "${lEMU_RES}" == *"ICMP ok"* ]] || [[ "${lEMU_RES}" == *"TCP-0 ok"* ]] || [[ "${lEMU_RES}" == *"TCP ok"* ]]; then
        print_output "[+] ${lEMU_RES}"
      else
        print_output "[*] ${lEMU_RES}"
      fi
    done < "${L10_SYS_EMU_RESULTS}"
  fi
}

pre_cleanup_emulator() {
  # this cleanup function is to ensure that we have no mounts from previous tests mounted
  local lCHECK_MOUNTS_ARR=()
  local lMOUNT=""

  print_output "[*] Checking for not unmounted proc, sys and run in log directory" "no_log"
  mapfile -t lCHECK_MOUNTS_ARR < <(mount | grep "${LOG_DIR}" | grep "proc\|sys\|run" || true)
  for lMOUNT in "${lCHECK_MOUNTS_ARR[@]}"; do
    print_output "[*] Unmounting ${lMOUNT}" "no_log"
    lMOUNT=$(echo "${lMOUNT}" | cut -d\  -f3)
    umount -l "${lMOUNT}" || true
  done
}

cleanup_tap() {
  local lTAP_CLEAN_ARR=()
  local lTAP_TO_CLEAN=""

  mapfile -t lTAP_CLEAN_ARR < <(ifconfig | grep tap | cut -d: -f1 || true)
  for lTAP_TO_CLEAN in "${lTAP_CLEAN_ARR[@]}"; do
    print_output "[*] Cleaning up TAP interface ${lTAP_TO_CLEAN}"
    tunctl -d "${lTAP_TO_CLEAN}" || print_error "[-] Error in tap cleanup"
  done
}

create_emulation_filesystem() {
  # based on the original firmAE script:
  # https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/makeImage.sh

  sub_module_title "Create Qemu filesystem for full system emulation"
  local lROOT_PATH="${1:-}"
  local lARCH_END="${2:-}"
  local lIMAGE_SIZE=""
  local lNVRAM_FILE_LIST=()
  local lNVRAM_FILE=""
  local lCURRENT_DIR=""
  export DEVICE="NA"
  export IMAGE_NAME=""
  IMAGE_NAME="$(basename "${lROOT_PATH}")_${lARCH_END}-${RANDOM}"

  export MNT_POINT="${LOG_PATH_MODULE}/emulation_tmp_fs_EMBA"
  if [[ -d "${MNT_POINT}" ]]; then
    MNT_POINT="${MNT_POINT}"-"${RANDOM}"
  fi
  mkdir "${MNT_POINT}" || true

  print_output "[*] Create Qemu filesystem for emulation - ${lROOT_PATH}.\\n"
  lIMAGE_SIZE="$(du -b --max-depth=0 "${lROOT_PATH}" | awk '{print $1}')"
  lIMAGE_SIZE=$((lIMAGE_SIZE + 400 * 1024 * 1024))

  print_output "[*] Size of filesystem for emulation - ${ORANGE}${lIMAGE_SIZE}${NC}.\\n"
  print_output "[*] Name of filesystem for emulation - ${ORANGE}${IMAGE_NAME}${NC}.\\n"
  qemu-img create -f raw "${LOG_PATH_MODULE}/${IMAGE_NAME}" "${lIMAGE_SIZE}"
  chmod a+rw "${LOG_PATH_MODULE}/${IMAGE_NAME}"

  print_output "[*] Creating Partition Table"
  echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "${LOG_PATH_MODULE}/${IMAGE_NAME}"

  print_output "[*] Identify Qemu Image device for ${ORANGE}${LOG_PATH_MODULE}/${IMAGE_NAME}${NC}"
  local lCNT=0
  while [[ "${DEVICE:-NA}" == "NA" ]]; do
    DEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
    lCNT=$((lCNT+1))
    if [[ "${DEVICE:-NA}" == "NA" ]] && [[ "${lCNT}" -gt 10 ]]; then
      print_output "[-] No Qemu Image device identified - return from ${FUNCNAME[0]}"
      return
    fi
    if [[ "${DEVICE:-NA}" != "NA" ]]; then
      break
    fi
    print_output "[*] Info: Initial identification for Qemu Image device for ${ORANGE}${LOG_PATH_MODULE}/${IMAGE_NAME}${NC} failed ... trying again"
    losetup || tee -a "${LOG_FILE}"
    losetup -D
    sleep 5
    losetup || tee -a "${LOG_FILE}"
  done

  print_output "[*] Qemu Image device: ${ORANGE}${DEVICE}${NC}"
  sleep 1
  print_output "[*] Device mapper created at ${ORANGE}${DEVICE}${NC}"

  print_output "[*] Creating Filesystem"
  sync
  mkfs.ext2 "${DEVICE}" || ( print_output "[-] Error in filesystem creation" && return )

  print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
  mount "${DEVICE}" "${MNT_POINT}" || ( print_output "[-] Error in mounting the filesystem" && return )

  if mount | grep -q "${MNT_POINT}"; then
    print_output "[*] Copy extracted root filesystem to new QEMU image"
    cp -prf "${lROOT_PATH}"/* "${MNT_POINT}"/ || (print_output "[-] Warning: Root filesystem not copied!" && return)

    print_output "[*] Binwalk v3+ creates raw files on extraction. We remove these files from our emulation root directory"
    find "${MNT_POINT}" -name "*.raw" -delete || true

    # ensure that the needed permissions for exec files are set correctly
    # This is needed at some firmwares have corrupted permissions on ELF or sh files
    print_output "[*] Multiple firmwares have broken links and script and ELF permissions - We fix them now"
    "${HELP_DIR}"/fix_bins_lnk_emulation.sh "${MNT_POINT}"

    print_output "[*] Creating EMBA emulation helper directories within the firmware environment"
    mkdir -p "${MNT_POINT}/firmadyne/libnvram/" || true
    mkdir -p "${MNT_POINT}/firmadyne/libnvram.override/" || true

    print_output "[*] Patching filesystem (chroot)"
    cp "$(command -v busybox)" "${MNT_POINT}" || true
    cp "$(command -v bash-static)" "${MNT_POINT}" || true

    if [[ -f "${S24_CSV_LOG}" ]]; then
      # kernelInit is getting the output of the init command line we get from s24
      if grep -q ";rdinit=" "${S24_CSV_LOG}"; then
        print_output "[*] Found ${ORANGE}rdinit${NC} entry for kernel - see ${ORANGE}${S24_LOG}${NC}:"
        grep ";rdinit=/" "${S24_CSV_LOG}" | cut -d\; -f4 | sed -e 's/.*rdinit=/rdinit=/' | awk '{print $1}'| sort -u | tee -a "${MNT_POINT}"/kernelInit
        tee -a "${LOG_FILE}" < "${MNT_POINT}"/kernelInit
      elif grep -q ";init=" "${S24_CSV_LOG}"; then
        print_output "[*] Found ${ORANGE}init${NC} entry for kernel - see ${ORANGE}${S24_LOG}${NC}:"
        grep ";init=/" "${S24_CSV_LOG}" | cut -d\; -f4 | sed -e 's/.*init=/init=/' | awk '{print $1}'| sort -u | tee -a "${MNT_POINT}"/kernelInit
        tee -a "${LOG_FILE}" < "${MNT_POINT}"/kernelInit
      fi
    else
      print_output "[-] No results from S24 kernel module found"
    fi

    print_output "[*] fixImage.sh (chroot)"
    cp "${MODULE_SUB_PATH}/fixImage.sh" "${MNT_POINT}" || true
    EMBA_BOOT=${EMBA_BOOT} EMBA_ETC=${EMBA_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /busybox ash /fixImage.sh || true | tee -a "${LOG_FILE}"

    print_output "[*] inferFile.sh (chroot)"
    # -> this re-creates init file and builds up the service which is ued from run_service.sh
    cp "${MODULE_SUB_PATH}/inferFile.sh" "${MNT_POINT}" || true
    EMBA_BOOT=${EMBA_BOOT} EMBA_ETC=${EMBA_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /bash-static /inferFile.sh | tee -a "${LOG_FILE}"

    print_output "[*] inferService.sh (chroot)"
    cp "${MODULE_SUB_PATH}/inferService.sh" "${MNT_POINT}" || true
    EMBA_BOOT=${EMBA_BOOT} EMBA_ETC=${EMBA_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /bash-static /inferService.sh | tee -a "${LOG_FILE}"

    if [[ -f "${MODULE_SUB_PATH}/injection_check.sh" ]]; then
      # injection checker - future extension
      local lINJECTION_MARKER="${RANDOM}"
      if [[ -d "${MNT_POINT}"/bin ]]; then
        cp "${MODULE_SUB_PATH}/injection_check.sh" "${MNT_POINT}"/bin/a || true
        chmod a+x "${MNT_POINT}/bin/a" || true
        sed -i 's/asdfqwertz/'"d34d_${lINJECTION_MARKER}"'/' "${MNT_POINT}"/bin/a || true
      fi
      if [[ -d "${MNT_POINT}"/sbin ]]; then
        cp "${MODULE_SUB_PATH}/injection_check.sh" "${MNT_POINT}"/sbin/a || true
        chmod a+x "${MNT_POINT}/sbin/a" || true
        sed -i 's/asdfqwertz/'"d34d_${lINJECTION_MARKER}"'/' "${MNT_POINT}"/sbin/a || true
      fi
      if [[ -f "${MNT_POINT}/sbin/a" ]] || [[ -f "${MNT_POINT}/bin/a" ]]; then
        print_output "[*] Generated injection scripts with marker ${ORANGE}${lINJECTION_MARKER}${NC}."
        cat "${MNT_POINT}"/bin/a
      fi
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
    # FirmAE/firmadyne recompiled binaries + addons
    local lBINARIES_ARR=( "busybox" "console" "libnvram_dbg.so" "libnvram_nondbg.so" "libnvram_ioctl_dbg.so" "libnvram_ioctl_nondbg.so" "strace" "netcat" "gdb" "gdbserver" )
    local lBINARY_NAME=""
    local lBINARY_PATH=""
    local lTMP_EXEC_64_CNT=0
    # quick check if we use stat/time or stat64/time64 on the target os - needed for libnvram
    lTMP_EXEC_64_CNT=$(find "${MNT_POINT}" -type f -name "*libc*" -not -path "*/firmadyne*" -exec objdump -t {} \; 2>/dev/null | grep -c " time64" || true)
    # default state for libnvram
    local lMUSL_VER="1.1.24"
    if [[ "${lTMP_EXEC_64_CNT}" -gt 0 ]]; then
      # we use the libnvram compiled with musl 1.2.x which moves all 32-bit archs to 64-bit time_t
      lMUSL_VER="1.2.5"
    fi

    for lBINARY_NAME in "${lBINARIES_ARR[@]}"; do
      lBINARY_PATH=$(get_binary "${lBINARY_NAME}" "${lARCH_END}" "${lMUSL_VER}")
      if [[ ! -f "${lBINARY_PATH}" ]]; then
        print_output "[-] Missing ${ORANGE}${lBINARY_NAME} / ${lBINARY_PATH:-NA} / ${lARCH_END}${NC} - no setup possible"
        continue
      fi
      print_output "[*] Setting up ${ORANGE}${lBINARY_NAME}${NC} - ${ORANGE}${lARCH_END}${NC} (${ORANGE}${lBINARY_PATH}${NC})"
      cp "${lBINARY_PATH}" "${MNT_POINT}/firmadyne/${lBINARY_NAME}"
      chmod a+x "${MNT_POINT}/firmadyne/${lBINARY_NAME}"
    done

    mknod -m 666 "${MNT_POINT}/firmadyne/ttyS1" c 4 65
    mknod -m 666 "${MNT_POINT}/firmadyne/ttyAMA1" c 4 65

    print_output "[*] Setting up emulation scripts"
    cp "${MODULE_SUB_PATH}/preInit.sh" "${MNT_POINT}/firmadyne/preInit.sh" || true
    chmod a+x "${MNT_POINT}/firmadyne/preInit.sh"

    # network.sh
    cp "${MODULE_SUB_PATH}/network.sh" "${MNT_POINT}/firmadyne/network.sh" || true
    chmod a+x "${MNT_POINT}/firmadyne/network.sh"

    # init_service.sh
    cp "${MODULE_SUB_PATH}/init_service.sh" "${MNT_POINT}/firmadyne/init_service.sh" || true
    chmod a+x "${MNT_POINT}/firmadyne/init_service.sh"

    # run_service.sh
    cp "${MODULE_SUB_PATH}/run_service.sh" "${MNT_POINT}/firmadyne/run_service.sh" || true
    chmod a+x "${MNT_POINT}/firmadyne/run_service.sh"

    chmod a+x "${MNT_POINT}/firmadyne/init"
    cp "${MNT_POINT}/firmadyne/init" "${LOG_PATH_MODULE}/firmadyne_init"

    lCURRENT_DIR=$(pwd)
    cd "${MNT_POINT}" || exit
    mapfile -t lNVRAM_FILE_LIST < <(find . -xdev -type f -name "*nvram*")
    for lNVRAM_FILE in "${lNVRAM_FILE_LIST[@]}"; do
      if file "${lNVRAM_FILE}" | grep -q "ASCII text"; then
        if ! [[ -d "${LOG_PATH_MODULE}"/nvram ]]; then
          mkdir "${LOG_PATH_MODULE}"/nvram
        fi
        lNVRAM_FILE="${lNVRAM_FILE/\.}"
        print_output "[*] Found possible NVRAM default file ${ORANGE}${lNVRAM_FILE}${NC} -> setup /firmadyne directory"
        echo "${lNVRAM_FILE}" >> "${LOG_PATH_MODULE}"/nvram/nvram_files
        cp ."${lNVRAM_FILE}" "${LOG_PATH_MODULE}"/nvram/
      fi
    done
    cd "${lCURRENT_DIR}" || exit

  else
    print_output "[!] Filesystem mount failed"
  fi
}

link_libnvram_so() {
  # pre-requisite is the mounted filesytem
  local lMNT_POINT="${1:-}"
  # default to debug mode with a lot of output - usually in the finale emulation mode we use the nondbg mode
  local lDBG_MODE="${2:-dbg}"

  # ensure we have a dbg libnvram for the initial identification
  if [[ -s "${lMNT_POINT}/firmadyne/libnvram.so" ]]; then
    rm "${lMNT_POINT}/firmadyne/libnvram.so"
  fi
  if [[ -s "${lMNT_POINT}/firmadyne/libnvram_ioctl.so" ]]; then
    rm "${lMNT_POINT}/firmadyne/libnvram_ioctl.so"
  fi
  if [[ -f "${lMNT_POINT}/firmadyne/libnvram_${lDBG_MODE}.so" ]]; then
    print_output "[*] Linking to ${lDBG_MODE} libnvram.so"
    ln -sr "${lMNT_POINT}/firmadyne/libnvram_${lDBG_MODE}.so" "${lMNT_POINT}/firmadyne/libnvram.so" || true
  fi
  if [[ -f "${lMNT_POINT}/firmadyne/libnvram_ioctl_${lDBG_MODE}.so" ]]; then
    print_output "[*] Linking to ${lDBG_MODE} libnvram_ioctl.so"
    ln -sr "${lMNT_POINT}/firmadyne/libnvram_ioctl_${lDBG_MODE}.so" "${lMNT_POINT}/firmadyne/libnvram_ioctl.so" || true
  fi
}

main_emulation() {
  R_PATH="${1:-}"
  local lARCH_END="${2:-}"
  export BOOTED="NONE"
  local lINIT_FILES_ARR=()

  create_emulation_filesystem "${R_PATH}" "${lARCH_END}"
  # here we set the global DEVICE which will be later used as local lDEVICE

  if [[ -f "${LOG_PATH_MODULE}"/firmadyne_init ]]; then
    print_ln
    print_output "[*] Processing init files:"
    local lINIT_FILE=""
    while read -r lINIT_FILE; do
      # check the number of '/' in our possible init file
      # if we are too deep (-gt 5) then we will skip this init entry
      # usually this looks the following
      # /bin/linuxrc
      local lINIT_DEPTH="${lINIT_FILE//[^\/]}"
      if [[ "${#lINIT_DEPTH}" -gt 5 ]]; then
        continue
      fi
      lINIT_FILES_ARR+=("${lINIT_FILE}")
      echo "${lINIT_FILE}" | tee -a "${LOG_FILE}"
    done < "${LOG_PATH_MODULE}"/firmadyne_init
  else
    print_output "[-] WARNING: init file not created! Processing backup dummy init"
    lINIT_FILES_ARR+=( "/dummy_init" )
  fi

  local lINDEX=1
  local lBAK_INIT_BACKUP=""
  local lBAK_INIT_ORIG=""
  local lINIT_OUT=""
  local lINIT_FNAME=""
  export IPS_INT_VLAN=()
  export ICMP=""
  export TCP_0=""
  export TCP=""
  local lSERVICE_NAME=""
  local lINIT_FILE=""

  for lINIT_FILE in "${lINIT_FILES_ARR[@]}"; do
    local lDEVICE="NA"
    lINIT_FNAME=$(basename "${lINIT_FILE}")
    # this is the main init entry - we modify it later for special cases:
    export KINIT="init=/firmadyne/preInit.sh"
    lINIT_OUT="${MNT_POINT}/firmadyne/preInit.sh"

    sub_module_title "[*] Processing init file ${ORANGE}${lINIT_FILE} (${lINDEX}/${#lINIT_FILES_ARR[@]})${NC}"
    if ! mount | grep -q "${MNT_POINT}"; then
      local lCNT=0
      while [[ "${lDEVICE:-NA}" == "NA" ]]; do
        lDEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${IMAGE_NAME}")"
        lCNT=$((lCNT+1))
        if [[ "${lDEVICE:-NA}" == "NA" ]] && [[ "${lCNT}" -gt 10 ]]; then
          print_output "[-] No Qemu Image device identified - continue now with next init entry"
          continue 2
        fi
        sleep 5
      done
      print_output "[*] Device mapper created at ${ORANGE}${lDEVICE}${NC}"
      print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
      mount "${lDEVICE}" "${MNT_POINT}" || true
    elif [[ -n "${DEVICE}" ]]; then
      lDEVICE="${DEVICE}"
    else
      print_output "[-] No Qemu Image device identified"
      break
    fi

    link_libnvram_so "${MNT_POINT}" "dbg"

    if [[ -n "${lBAK_INIT_ORIG}" ]]; then
      print_output "[*] Restoring old init file: ${lBAK_INIT_ORIG}"
      cp -pr "${lBAK_INIT_BACKUP}" "${lBAK_INIT_ORIG}" || print_error "[-] Error restoring old init file ${lBAK_INIT_ORIG}"
      lBAK_INIT_BACKUP=""
      lBAK_INIT_ORIG=""
    fi

    print_ln
    print_output "[*] Firmware Init file details:"
    print_output "$(indent "$(orange "$(file "${MNT_POINT}""${lINIT_FILE}" || true)")")"

    print_output "[*] EMBA Init starter file details:"
    print_output "$(indent "$(orange "$(file "${lINIT_OUT}" || true)")")"
    print_ln

    # we deal with something which is not a script:
    if file "${MNT_POINT}""${lINIT_FILE}" | grep -q "symbolic link\|ELF"; then
      print_output "[*] Backup original init file ${ORANGE}${lINIT_OUT}${NC}"
      lBAK_INIT_ORIG="${lINIT_OUT}"
      lBAK_INIT_BACKUP="${LOG_PATH_MODULE}"/"$(basename "${lINIT_OUT}".init)"

      # write the init ELF file or sym link to the EMBA preInit script:
      # INIT_OUT="${MNT_POINT}""/firmadyne/preInit.sh"
      cp -pr "${lINIT_OUT}" "${lBAK_INIT_BACKUP}" || true

      print_output "[*] Add ${lINIT_FILE} entry to ${ORANGE}${lINIT_OUT}${NC}"
      # we always add the identified init entry to the EMBA preInit script
      if ! (grep -q "${lINIT_FILE}" "${lINIT_OUT}"); then
        echo "${lINIT_FILE} &" >> "${lINIT_OUT}" || true
        # ensure we give the system some time to boot via the original init file
        echo "/firmadyne/busybox sleep 60" >> "${lINIT_OUT}" || true
      fi
    fi

    local lFS_MOUNTS_INIT_ARR=()
    # if we are dealing with a startup script we are going to use this as the init entry
    # and add our starters at the end of the original script
    if file "${MNT_POINT}""${lINIT_FILE}" | grep -q "text executable\|ASCII text"; then
      # we deal with a startup script
      lINIT_OUT="${MNT_POINT}""${lINIT_FILE}"

      export KINIT="init=${lINIT_FILE}"

      find "${lINIT_OUT}" -xdev -maxdepth 1 -ls || true
      print_output "[*] Backup original init file ${ORANGE}${lINIT_OUT}${NC}"
      lBAK_INIT_ORIG="${lINIT_OUT}"
      lBAK_INIT_BACKUP="${LOG_PATH_MODULE}"/"$(basename "${lINIT_OUT}".init)"
      cp -pr "${lINIT_OUT}" "${lBAK_INIT_BACKUP}"

      # identify mount operations for later handling and disabling
      mapfile -t lFS_MOUNTS_INIT_ARR < <(grep -E "^mount\ -t\ .*\ .*mtd.* /.*" "${MNT_POINT}""${lINIT_FILE}" | sort -u || true)

      # just in case we have issues with permissions
      chmod +x "${MNT_POINT}""${lINIT_FILE}"

      # just in case there is an exit in the init -> comment it
      sed -i -r 's/(.*exit\ [0-9])$/\#\ \1/' "${MNT_POINT}""${lINIT_FILE}"
    fi

    # Beside the check of init we also try to find other mounts for further filesystems
    # probably we need to tweak this further to also find mounts in binaries - strings?!?
    local lFS_MOUNTS_FS_ARR=()
    if [[ -d "${FIRMWARE_PATH}" ]]; then
      # TODO: fix the tr commands do escape_print or so
      mapfile -t lFS_MOUNTS_FS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -exec grep -a -h -E "^mount\ -t\ .*\ .*mtd.* /.*" {} \; 2>/dev/null | tr -d '"' | tr -d '$' | sort -u || true)
    fi

    local lFS_MOUNTS_ARR=()
    lFS_MOUNTS_ARR=( "${lFS_MOUNTS_INIT_ARR[@]}" "${lFS_MOUNTS_FS_ARR[@]}" )
    mapfile -t lFS_MOUNTS_ARR < <(printf "%s\n" "${lFS_MOUNTS_ARR[@]}" | sort -u)

    handle_fs_mounts "${lINIT_FILE}" "${lFS_MOUNTS_ARR[@]}"

    if (grep -q "preInit.sh" "${MNT_POINT}""${lINIT_FILE}"); then
      # if have our own backup init script we need to remove our own entries now
      sed -i -r 's%(.*preInit.sh.*)%\#\ \1%' "${MNT_POINT}""${lINIT_FILE}"
      sed -i -r 's%(/firmadyne/init_service.sh.*)%\#\ \1%' "${MNT_POINT}""${lINIT_FILE}"
      sed -i -r 's%(/firmadyne/network.sh.*)%\#\ \1%' "${MNT_POINT}""${lINIT_FILE}"
      sed -i -r 's%(/firmadyne/run_service.sh.*)%\#\ \1%' "${MNT_POINT}""${lINIT_FILE}"
    fi

    if [[ "${lINIT_OUT}" != *"preInit.sh" ]]; then
      if ( grep -q "/firmadyne/preInit.sh" "${lINIT_OUT}"); then
        print_output "[*] preInit.sh entry already available in init ${ORANGE}${lINIT_OUT}${NC} -> removing now"
        sed -i '/\/firmadyne\/preInit\.sh\ &/d' "${lINIT_OUT}"
      fi
      echo "/firmadyne/preInit.sh &" >> "${lINIT_OUT}" || print_error "[-] Some error occured while adding the preInit.sh entry to ${lINIT_OUT}"
    fi

    if ( grep -q "/firmadyne/init_service.sh" "${lINIT_OUT}"); then
      print_output "[*] init_server.sh entry already available in init ${ORANGE}${lINIT_OUT}${NC} -> removing now"
      sed -i '/\/firmadyne\/init_service\.sh\ &/d' "${lINIT_OUT}"
    fi
    if [[ -f "${MNT_POINT}/firmadyne/startup_service" ]]; then
      while read -r lSERVICE_NAME; do
        print_output "[*] Created init service entry for starting service ${ORANGE}${lSERVICE_NAME}${NC}"
      done < "${MNT_POINT}/firmadyne/startup_service"
      echo "/firmadyne/init_service.sh &" >> "${lINIT_OUT}" || print_error "[-] Some error occured while adding the init_service entry to ${lINIT_OUT}"
    fi

    if ( grep -q "/firmadyne/network.sh" "${lINIT_OUT}"); then
      print_output "[*] network.sh entry already available in init ${ORANGE}${lINIT_OUT}${NC} -> removing now"
      sed -i '/\/firmadyne\/network\.sh\ &/d' "${lINIT_OUT}"
    fi

    print_output "[*] Add network.sh entry to ${ORANGE}${lINIT_OUT}${NC}"
    echo "" >> "${lINIT_OUT}" || true
    echo "/firmadyne/network.sh &" >> "${lINIT_OUT}" || print_error "[-] Some error occured while adding the network.sh entry to ${lINIT_OUT}"

    if ( grep -q "/firmadyne/run_service.sh" "${lINIT_OUT}"); then
      print_output "[*] run_service.sh entry already available in init ${ORANGE}${lINIT_OUT}${NC} -> removing now"
      sed -i '/\/firmadyne\/run_service\.sh\ &/d' "${lINIT_OUT}"
    fi
    if [[ -f "${MNT_POINT}/firmadyne/service" ]]; then
      while read -r lSERVICE_NAME; do
        print_output "[*] Created service entry for starting service ${ORANGE}${lSERVICE_NAME}${NC}"
      done < "${MNT_POINT}/firmadyne/service"
      echo "/firmadyne/run_service.sh &" >> "${lINIT_OUT}" || print_error "[-] Some error occured while adding the run_service entry to ${lINIT_OUT}"
    fi

    # ensure we have not sleep entry and it is not the EMBA backup init script
    if ( grep -q "/firmadyne/busybox sleep 36000" "${lINIT_OUT}"); then
      print_output "[*] busybox sleep 36000 entry already available in init ${ORANGE}${lINIT_OUT}${NC}  -> removing now"
      sed -i '/\/firmadyne\/busybox\ sleep\ 36000/d' "${lINIT_OUT}"
    fi
    if ! ( grep -q "/firmadyne/busybox sleep 36000" "${lINIT_OUT}") && ! (grep -q "Execute EMBA " "${lINIT_OUT}"); then
      # trendnet TEW-828DRU_1.0.7.2, etc...
      echo "/firmadyne/busybox sleep 36000" >> "${lINIT_OUT}" || print_error "[-] Some error occured while adding the busybox sleep entry to ${lINIT_OUT}"
    fi

    print_ln
    print_output "[*] EMBA init starter file: ${ORANGE}${lINIT_OUT}${NC}"
    tee -a "${LOG_FILE}" < "${lINIT_OUT}" || true
    if file "${MNT_POINT}""${lINIT_FILE}" | grep -q "text executable\|ASCII text"; then
      print_ln
      print_output "[*] Firmware Init file details: ${ORANGE}${lINIT_FILE}${NC}"
      tee -a "${LOG_FILE}" < "${MNT_POINT}""${lINIT_FILE}"
    fi

    print_ln
    print_output "[*] EMBA Target filesytem:"
    find "${MNT_POINT}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}" || true

    print_ln
    print_output "[*] EMBA emulation helpers directory:"
    find "${MNT_POINT}"/firmadyne -xdev -ls | tee -a "${LOG_FILE}" || true
    print_ln

    ### set default network values for network identification mode
    local lIP_ADDRESS="192.168.0.1"
    local lNETWORK_MODE="None"
    local lNETWORK_DEVICE="br0"
    local lETH_INT="eth0"
    set_network_config "${lIP_ADDRESS}" "${lNETWORK_MODE}" "${lNETWORK_DEVICE}" "${lETH_INT}"

    print_output "[*] Unmounting QEMU Image" "no_log"
    umount_qemu_image "${lDEVICE}"
    delete_device_entry "${IMAGE_NAME}" "${lDEVICE}" "${MNT_POINT}"

    check_qemu_instance_l10

    identify_networking_emulation "${IMAGE_NAME}" "${lARCH_END}" "${lINIT_FILE}"
    get_networking_details_emulation "${IMAGE_NAME}"

    print_output "[*] Firmware ${ORANGE}${IMAGE_NAME}${NC} finished for identification of the network configuration"

    local lF_STARTUP=0
    if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
      cat "${LOG_PATH_MODULE}"/qemu.initial.serial.log >> "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}".log
      write_link "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}".log

      ###############################################################################################
      # if we were running into issues with the network identification we poke with rdinit vs init:
      # lets check if we have found a startup procedure (preInit script) from EMBA - if not we try it with the other init
      lF_STARTUP=$(grep -a -c "EMBA preInit script starting" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)
      lF_STARTUP=$(( "${lF_STARTUP}" + "$(grep -a -c "Network configuration - ACTION" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)" ))
    else
      print_output "[-] No Qemu log file generated ... some weird error occured"
      return
    fi
    # print_output "[*] Found $ORANGE$lF_STARTUP$NC EMBA startup entries."
    print_ln

    # the following condition is for switching and testing a different init= -> rdinit=
    if [[ "${#PANICS[@]}" -gt 0 ]] || [[ "${lF_STARTUP}" -eq 0 ]] || [[ "${DETECTED_IP}" -eq 0 ]]; then
      # if we are running into a kernel panic during the network detection we are going to check if the
      # panic is caused from an init failure. If so, we are trying the other init kernel command (init vs rdinit)
      print_output "[*] Info: lF_STARTUP: ${lF_STARTUP} / lNETWORK_MODE: ${lNETWORK_MODE} / DETECTED_IP: ${DETECTED_IP} / PANICS: ${#PANICS[@]}"
      if [[ "${PANICS[*]}" == *"Kernel panic - not syncing: Attempted to kill init!"* || "${PANICS[*]}" == *"Kernel panic - not syncing: No working init found."* ]]; then
        mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_base_init.log
        print_output "[!] Identified Kernel panic ... switching init from ${KINIT}"
        switch_inits "${KINIT}"

        # re-identify the network via other init configuration
        identify_networking_emulation "${IMAGE_NAME}" "${lARCH_END}" "${lINIT_FILE}"
        get_networking_details_emulation "${IMAGE_NAME}"

        print_output "[*] Firmware ${ORANGE}${IMAGE_NAME}${NC} finished for identification of the network configuration"
        if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
          mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_new_init.log
          write_link "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_new_init.log
        else
          print_output "[-] No Qemu log file generated ... some weird error occured"
        fi
        print_ln

      elif [[ "${lF_STARTUP}" -eq 0 && "${lNETWORK_MODE}" == "None" ]] || \
        [[ "${lF_STARTUP}" -eq 0 && "${lNETWORK_MODE}" == "default" ]] || [[ "${DETECTED_IP}" -eq 0 ]]; then
        print_output "[!] Possible init issue ... switching init from ${KINIT}"
        local lPORTS_1st=0
        local lCOUNTING_1st=0
        mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_base_init.log
        lCOUNTING_1st=$(wc -l < "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_base_init.log)
        lPORTS_1st=$(grep -a "inet_bind" "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_base_init.log | sort -u | wc -l | awk '{print $1}' || true)
        switch_inits "${KINIT}"

        # re-identify the network via other init configuration
        identify_networking_emulation "${IMAGE_NAME}" "${lARCH_END}" "${lINIT_FILE}"
        get_networking_details_emulation "${IMAGE_NAME}"

        local lPORTS_2nd=0
        local lCOUNTING_2nd=0
        local lF_STARTUP=0
        if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
          print_output "[*] qemu.initial.serial.log detected and checking for STARTUP and Service data"
          # now we need to check if something is better now or we should switch back to the original init
          lF_STARTUP=$(grep -a -c "EMBA preInit script starting" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)
          lF_STARTUP=$(( "${lF_STARTUP}" + "$(grep -a -c "Network configuration - ACTION" "${LOG_PATH_MODULE}"/qemu.initial.serial.log || true)" ))
          lCOUNTING_2nd=$(wc -l < "${LOG_PATH_MODULE}"/qemu.initial.serial.log)
          lPORTS_2nd=$(grep -a "inet_bind" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | sort -u | wc -l | awk '{print $1}' || true)
          # IPS_INT_VLAN is always at least 1 for the default configuration
        else
          print_output "[-] NO qemu.initial.serial.log detected and NO checking for STARTUP and Service data possible"
        fi

        print_output "[*] lPORTS_1st: ${lPORTS_1st} / lPORTS_2nd: ${lPORTS_2nd} / lF_STARTUP: ${lF_STARTUP}"
        if [[ "${#PANICS[@]}" -gt 0 ]] || [[ "${lF_STARTUP}" -eq 0 && "${#IPS_INT_VLAN[@]}" -lt 2 ]] || \
          [[ "${DETECTED_IP}" -eq 0 ]]; then
          if [[ "${#PANICS[@]}" -gt 0 ]]; then
            # on a Kernel panic we always switch back
            print_output "[!] Identified Kernel panic ... switching init back from ${KINIT}"
            switch_inits "${KINIT}"
          elif [[ "${lPORTS_1st}" -gt "${lPORTS_2nd}" ]]; then
            print_output "[!] Network services issue ... switching init back from ${KINIT}"
            switch_inits "${KINIT}"
          # we only switch back if the first check has more output generated
          elif [[ "${lCOUNTING_1st}" -gt "${lCOUNTING_2nd}" ]] && [[ "${lPORTS_1st}" -ge "${lPORTS_2nd}" ]]; then
            print_output "[!] Network services issue and log file size ... switching init back from ${KINIT}"
            switch_inits "${KINIT}"
          fi
        fi

        print_output "[*] Firmware ${ORANGE}${IMAGE_NAME}${NC} finished for identification of the network configuration"
        if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
          mv "${LOG_PATH_MODULE}"/qemu.initial.serial.log "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_new_init.log
          write_link "${LOG_PATH_MODULE}"/qemu.initial.serial_"${IMAGE_NAME}"_"${lINIT_FNAME}"_new_init.log
        else
          print_output "[-] No Qemu log file generated ... some weird error occured"
        fi
        print_ln

        export PANICS=()
      fi
    fi
    ###############################################################################################

    if [[ "${#IPS_INT_VLAN[@]}" -gt 0 && "${#PANICS[@]}" -eq 0 ]]; then
      nvram_check "${IMAGE_NAME}"
      print_bar ""
      print_output "[*] Identified the following network configuration options:"
      local lIP_CFG=""
      local lINTERFACE_CFG=""
      local lNETWORK_INTERFACE_CFG=""
      local lVLAN_CFG=""
      local lCFG_CFG=""
      local lIPS_INT_VLAN_CFG=""
      local lNETWORK_MODE=""
      local lNETWORK_DEVICE=""
      local lNW_ENTRY_PRIO=0
      local lIPS_INT_VLAN_TMP=()

      # sort it
      mapfile -t IPS_INT_VLAN < <(printf "%s\n" "${IPS_INT_VLAN[@]}" | sort -t ';' -k 1,1r -k 5,5n)
      # make it unique
      mapfile -t IPS_INT_VLAN < <(printf "%s\n" "${IPS_INT_VLAN[@]}" | uniq)

      for lIPS_INT_VLAN_CFG in "${IPS_INT_VLAN[@]}"; do
        lNW_ENTRY_PRIO="${lIPS_INT_VLAN_CFG/\;*}"
        lIP_CFG=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f2)
        lINTERFACE_CFG=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f3)
        lNETWORK_INTERFACE_CFG=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f4)
        lVLAN_CFG=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f5)
        lCFG_CFG=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f6)
        if [[ "${lIPS_INT_VLAN_TMP[*]}" == *"${lIP_CFG};${lINTERFACE_CFG};${lNETWORK_INTERFACE_CFG};${lVLAN_CFG};${lCFG_CFG}"* ]]; then
          continue
        fi
        lIPS_INT_VLAN_TMP+=( "${lNW_ENTRY_PRIO}"\;"${lIP_CFG}"\;"${lINTERFACE_CFG}"\;"${lNETWORK_INTERFACE_CFG}"\;"${lVLAN_CFG}"\;"${lCFG_CFG}" )
        print_output "$(indent "$(orange "${lIP_CFG}"" - ""${lINTERFACE_CFG}"" - ""${lNETWORK_INTERFACE_CFG}"" - ""${lVLAN_CFG}"" - ""${lCFG_CFG}"" - ""${lNW_ENTRY_PRIO}")")"
      done
      print_ln

      IPS_INT_VLAN=("${lIPS_INT_VLAN_TMP[@]}")

      for lIPS_INT_VLAN_CFG in "${IPS_INT_VLAN[@]}"; do
        emulation_with_config "${lIPS_INT_VLAN_CFG}"

        if [[ "${TCP}" != "ok" ]]; then
          print_output "[*] We are in the emergency init switch mode now"
          # just in case we have no running TCP service detected we try the other init mechanism (rdinit vs init)
          # this is only done if we have already switched inits and our first detection run has also network services detected
          switch_inits "${KINIT}"
          emulation_with_config "${lIPS_INT_VLAN_CFG}"
          # we do not care about the results and switch back to the original init
          # later on we are running the same process again
          switch_inits "${KINIT}"
        fi
        if [[ $(grep -h "udp.*open\ \|tcp.*open\ " "${ARCHIVE_PATH}"/*"${NMAP_LOG}" 2>/dev/null | awk '{print $1}' | sort -u | wc -l || true) -ge "${MIN_TCP_SERV}" ]]; then
          break 2
        fi
      done
    else
      print_output "[!] No further emulation steps are performed"
    fi

    cleanup_emulator "${IMAGE_NAME}"

    print_output "[*] Processing init file ${ORANGE}${lINIT_FILE}${NC} (${lINDEX}/${#lINIT_FILES_ARR[@]}) finished"
    print_bar ""
    ((lINDEX+=1))
  done

  delete_device_entry "${IMAGE_NAME}" "${lDEVICE}" "${MNT_POINT}"
}

emulation_with_config() {
  lIPS_INT_VLAN_CFG="${1:-}"
  local lRESTARTED_EMULATION="${2:-0}"

  SYS_ONLINE=0

  print_ln
  print_output "[*] Testing system emulation with configuration: ${ORANGE}${lIPS_INT_VLAN_CFG//\;/-}${NC}."

  cleanup_tap
  check_qemu_instance_l10

  local lENTRY_PRIO=""
  local lVLAN_ID=""
  lENTRY_PRIO="${lIPS_INT_VLAN_CFG/\;*}"
  IP_ADDRESS_=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f2)
  lNETWORK_DEVICE=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f3)
  lETH_INT=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f4)
  lVLAN_ID=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f5)
  lNETWORK_MODE=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f6)
  export NMAP_LOG="nmap_emba_${lIPS_INT_VLAN_CFG//\;/-}.txt"

  setup_network_emulation "${lIPS_INT_VLAN_CFG}"
  run_emulated_system "${IP_ADDRESS_}" "${IMAGE_NAME}" "${lINIT_FILE}" "${lARCH_END}"

  check_online_stat "${lIPS_INT_VLAN_CFG}" "${IMAGE_NAME}" &
  local lCHECK_ONLINE_STAT_PID="$!"

  print_keepalive "${LOG_PATH_MODULE}/qemu.final.serial.log" "${IMAGE_NAME}" &
  local lALIVE_PID="$!"
  disown "${lALIVE_PID}" 2> /dev/null || true

  # we kill this process from "check_online_stat"
  tail -F "${LOG_PATH_MODULE}/qemu.final.serial.log" 2>/dev/null | grep -a -v "klogd" || true
  if [[ -e /proc/"${lCHECK_ONLINE_STAT_PID}" ]]; then
    kill -9 "${lCHECK_ONLINE_STAT_PID}" || true
  fi

  kill "${lALIVE_PID}"

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
    if grep -q "udp.*open\ \|tcp.*open\ " "${ARCHIVE_PATH}"/*"${NMAP_LOG}" 2>/dev/null; then
      TCP="ok"
      SYS_ONLINE=1
      BOOTED="yes"
    fi

    # remove tmp files for next round
    rm "${TMP_DIR}"/online_stats.tmp || true
  fi

  write_results "${ARCHIVE_PATH}" "${R_PATH}" "${RESULT_SOURCE:-EMBA}" "${lNETWORK_MODE}" "${lETH_INT}" "${lVLAN_ID}" "${lINIT_FILE}" "${lNETWORK_DEVICE}"
  print_output "[*] Call to stop emulation process - Source ${FUNCNAME[0]}" "no_log"
  stopping_emulation_process "${IMAGE_NAME}"
  cleanup_emulator "${IMAGE_NAME}"

  if [[ -f "${LOG_PATH_MODULE}"/qemu.final.serial.log ]]; then
    mv "${LOG_PATH_MODULE}"/qemu.final.serial.log "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${lIPS_INT_VLAN_CFG//\;/-}"-"${lINIT_FNAME}".log
  fi

  if [[ "${SYS_ONLINE}" -eq 1 ]]; then
    print_ln
    print_output "[+] System emulation was successful."
    if [[ -f "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${lIPS_INT_VLAN_CFG//\;/-}"-"${lINIT_FNAME}".log ]]; then
      print_output "[+] System should be available via IP ${ORANGE}${IP_ADDRESS_}${GREEN}." "" "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${lIPS_INT_VLAN_CFG//\;/-}"-"${lINIT_FNAME}".log
    else
      print_output "[+] System should be available via IP ${ORANGE}${IP_ADDRESS_}${GREEN}."
    fi
    print_ln

    if [[ "${TCP}" == "ok" ]]; then
      if [[ $(grep -h "udp.*open\ \|tcp.*open\ " "${ARCHIVE_PATH}"/*"${NMAP_LOG}" 2>/dev/null | awk '{print $1}' | sort -u | wc -l || true) -ge "${MIN_TCP_SERV}" ]]; then
        print_output "[+] Network services are available - no further emulation runs are needed" "" "${ARCHIVE_PATH}/${NMAP_LOG}"
      else
        print_output "[+] Network services are available - further emulation runs are needed." "" "${ARCHIVE_PATH}/${NMAP_LOG}"
      fi
      print_ln
    fi

    create_emulation_archive "${KERNEL}" "${IMAGE}" "${ARCHIVE_PATH}" "${lIPS_INT_VLAN_CFG//\;/-}"
  else
    if [[ "${L10_DEBUG_MODE}" -eq 1 ]]; then
      print_output "[-] ${ORANGE}Debug mode:${NC} No working emulation - ${ORANGE}creating${NC} emulation archive ${ORANGE}${ARCHIVE_PATH}${NC}."
      create_emulation_archive "${KERNEL}" "${IMAGE}" "${ARCHIVE_PATH}" "${lIPS_INT_VLAN_CFG//\;/-}"
    else
      print_output "[-] No working emulation - removing emulation archive ${ORANGE}${ARCHIVE_PATH}${NC}."
      if [[ -f "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${lIPS_INT_VLAN_CFG//\;/-}"-"${lINIT_FNAME}".log ]]; then
        write_link "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${lIPS_INT_VLAN_CFG//\;/-}"-"${lINIT_FNAME}".log
      fi
      # print_output "[-] Emulation archive: $ARCHIVE_PATH."
      # create_emulation_archive "$ARCHIVE_PATH"
      rm -r "${ARCHIVE_PATH}" || true
    fi
  fi

  if [[ -f "${LOG_PATH_MODULE}"/nvram/nvram_files_final_ ]]; then
    mv "${LOG_PATH_MODULE}"/nvram/nvram_files_final_ "${LOG_PATH_MODULE}"/nvram/nvram_files_"${IMAGE_NAME}".bak
  fi
  if ! [[ -f "${LOG_PATH_MODULE}/qemu.final.serial_${IMAGE_NAME}-${lIPS_INT_VLAN_CFG//\;/-}-${lINIT_FNAME}.log" ]]; then
    print_output "[!] Warning: No Qemu log file generated for ${ORANGE}${IMAGE_NAME}-${lIPS_INT_VLAN_CFG//\;/-}-${lINIT_FNAME}${NC}"
  fi

  # if we have created our qemu log file and TCP is not ok we check for additional IP addresses and
  # rerun the emulation if a different IP address was found
  if [[ -f "${LOG_PATH_MODULE}/qemu.final.serial_${IMAGE_NAME}-${lIPS_INT_VLAN_CFG//\;/-}-${lINIT_FNAME}.log" ]]; then
    local lTEMP_RUN_IPs_ARR=()
    local lTMP_IP=""
    # lets check if the system has configured some different IP address then expected
    # we use the output of ipconfig from the qemu logs for this check
    # first: generate an array with the possible ip addresses (remove already local addresses like 127.0.0.)
    mapfile -t lTEMP_RUN_IPs_ARR < <(grep -a -o -E "inet addr:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" \
      "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${lIPS_INT_VLAN_CFG//\;/-}"-"${lINIT_FNAME}".log | \
      grep -v "127.0.0." | grep -v "${IP_ADDRESS_}" | cut -d ':' -f2 | sort -u || true)
    for lTMP_IP in "${lTEMP_RUN_IPs_ARR[@]}"; do
      # check every detected ip address against our real system ip address
      # if we have some other ip address detected we move on:
      if [[ "${lTMP_IP}" != "${IP_ADDRESS_}" ]]; then
        # check every ip address for our used interfaces (ethX/brX)
        # if we find a typical used interface with the changed IP address we will check it again
        if (grep -B1 "inet addr:${lTMP_IP}" "${LOG_PATH_MODULE}"/qemu.final.serial_"${IMAGE_NAME}"-"${lIPS_INT_VLAN_CFG//\;/-}"-"${lINIT_FNAME}".log | grep -q "^eth\|^br"); then
          print_output "[!] WARNING: Detected possible IP address change during emulation process from ${ORANGE}${IP_ADDRESS_}${MAGENTA} to address ${ORANGE}${lTMP_IP}${NC}"
          # we restart the emulation with the identified IP address for a maximum of one time
          if [[ $(grep -h "udp.*open\ \|tcp.*open\ " "${ARCHIVE_PATH}"/*"${NMAP_LOG}" 2>/dev/null | awk '{print $1}' | sort -u | wc -l || true) -lt "${MIN_TCP_SERV}" ]]; then
            if [[ "${lRESTARTED_EMULATION:-1}" -eq 0 ]]; then
              print_output "[!] Emulation re-run with IP ${ORANGE}${lTMP_IP}${MAGENTA} needed and executed"
              lIPS_INT_VLAN_CFG="${lENTRY_PRIO}"\;"${lTMP_IP}"\;"${lNETWORK_DEVICE}"\;"${lETH_INT}"\;"${lVLAN_ID}"\;"${lNETWORK_MODE}"
              IPS_INT_VLAN+=( "${lIPS_INT_VLAN_CFG}" )
              emulation_with_config "${lIPS_INT_VLAN_CFG}" 1
            else
              print_output "[!] Emulation re-run with IP ${ORANGE}${lTMP_IP}${MAGENTA} needed but ${ORANGE}not executed${NC}"
            fi
          else
            print_output "[!] Emulation re-run with IP ${ORANGE}${lTMP_IP}${MAGENTA} could be performed but ${ORANGE}network services already available${NC}"
          fi
        fi
      fi
    done
  fi
}

switch_inits() {
  # KINIT is global but for readability:
  KINIT="${1:-}"
  if [[ "${KINIT:0:2}" == "rd" ]]; then
    print_output "[*] Note: Switching rdinit to init"
    # strip rd from rdinit
    KINIT="${KINIT:2}"
  else
    print_output "[*] Note: Switching init to rdinit"
    # make rdinit from init
    KINIT="rd""${KINIT}"
  fi
}

umount_qemu_image() {
  local lDEVICE=${1:-}
  sync
  disable_strict_mode "${STRICT_MODE}" 0
  if ! umount "${lDEVICE}"; then
    print_output "[*] Warning: Normal umount was not successful. Trying to enforce unmounting of ${ORANGE}${lDEVICE}${NC}."
    umount -l "${lDEVICE}" || true
    umount -f "${lDEVICE}" || true
    sleep 5
  fi
  enable_strict_mode "${STRICT_MODE}" 0
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
  local lINIT_FILE=${1:-}
  shift 1
  local lFS_MOUNTS_ARR=("$@")
  local lFS_MOUNT=""

  for lFS_MOUNT in "${lFS_MOUNTS_ARR[@]}"; do
    if [[ -z "${lFS_MOUNT}" ]]; then
      continue
    fi
    local lMOUNT_PT=""
    local lMOUNT_FS=""
    local lFS_FIND=""

    local lINIT_FILE_PATH="${MNT_POINT}${lINIT_FILE}"
    print_output "[*] Found filesystem mount and analysing it: ${ORANGE}${lFS_MOUNT}${NC}"
    # as the original mount will not work, we need to remove it from the startup file:
    if [[ -f "${lINIT_FILE_PATH}" ]]; then
      sed -i 's|'"${lFS_MOUNT}"'|\#'"${lFS_MOUNT}"'|g' "${lINIT_FILE_PATH}"
    else
      print_error "[-] Init file ${lINIT_FILE_PATH} NOT available ... returning but this could result in further issues"
      return
    fi

    lMOUNT_PT=$(echo "${lFS_MOUNT}" | awk '{print $5}')
    lMOUNT_FS=$(echo "${lFS_MOUNT}" | grep " \-t " | sed 's/.*-t //g' | awk '{print $1}')
    if [[ "${lMOUNT_FS}" != *"jffs"* ]] && [[ "${lMOUNT_FS}" != *"cramfs"* ]]; then
      print_output "[-] Warning: ${ORANGE}${lMOUNT_FS}${NC} filesystem currently not supported"
      print_output "[-] Warning: If further results are wrong please open a ticket"
    fi
    if [[ "${lMOUNT_PT}" != *"/"* ]]; then
      lMOUNT_PT=$(echo "${lFS_MOUNT}" | awk '{print $NF}')
      if [[ "${lMOUNT_PT}" != *"/"* ]]; then
        print_output "[-] Warning: Mount point ${ORANGE}${lMOUNT_PT}${NC} currently not supported"
        print_output "[-] Warning: If further results are wrong please open a ticket"
      fi
    fi
    # we test for paths including the lMOUNT_FS part like "jffs2" in the path
    lFS_FIND=$(find "${LOG_DIR}"/firmware -path "*/*${lMOUNT_FS}*_extract" | head -1 || true)

    print_output "[*] Identified mount point: ${ORANGE}${lMOUNT_PT}${NC}"
    print_output "[*] Identified mounted fs: ${ORANGE}${lMOUNT_FS}${NC}"

    if [[ "${lFS_FIND}" =~ ${lMOUNT_FS} ]]; then
      print_output "[*] Possible FS target found: ${ORANGE}${lFS_FIND}${NC}"
    else
      print_output "[-] No FS target found"
    fi
    print_output "[*] Root system mount point: ${ORANGE}${MNT_POINT}${NC}"

    if [[ "${R_PATH}" == *"${lFS_FIND}"* ]]; then
      print_output "[-] Found our own root directory ... skipping"
      print_output "[*] R_PATH: ${R_PATH}"
      print_output "[*] FS_FIND: ${lFS_FIND}"
      continue
    fi

    find "${lFS_FIND}" -xdev -ls || true

    print_output "[*] Identify system areas in the to-mount area:"
    local lLINUX_PATHS_ARR=( "bin" "boot" "dev" "etc" "home" "lib" "mnt" "opt" "proc" "root" "sbin" "srv" "tmp" "usr" "var" )
    local lL_PATH=""
    local lN_PATH=""
    local lX_PATH=""
    local lNEWPATH_ARR=()
    local lNEWPATH_tmp_ARR=()
    local lNEWPATH_test_ARR=()

    for lL_PATH in "${lLINUX_PATHS_ARR[@]}"; do
      mapfile -t lNEWPATH_tmp_ARR < <(find "${lFS_FIND}" -path "*/${lL_PATH}" -type d | sed "s/\/${lL_PATH}\/*/\//g")
      mapfile -t lNEWPATH_test_ARR < <(find "${lFS_FIND}" -path "*/${lL_PATH}" -type d)
      lNEWPATH_ARR+=( "${lNEWPATH_tmp_ARR[@]}" )
      if [[ -d "${MNT_POINT}"/"${lL_PATH}" ]]; then
        for lX_PATH in "${lNEWPATH_test_ARR[@]}"; do
          print_output "[*] Copy ${lX_PATH} to ${MNT_POINT}/${lL_PATH}/"
          cp -pr --update=none "${lX_PATH}"/* "${MNT_POINT}"/"${lL_PATH}"/
        done
      fi
    done

    mapfile -t lNEWPATH_ARR < <(printf "%s\n" "${lNEWPATH_ARR[@]}" | sort -u)

    for lN_PATH in "${lNEWPATH_ARR[@]}"; do
      if [[ -z "${lN_PATH}" ]]; then
        continue
      fi
      print_output "[*] PATH found: ${lN_PATH}"
      find "${lN_PATH}" -xdev -ls || true

      if ! [[ -d "${MNT_POINT}""${lMOUNT_PT}" ]]; then
        print_output "[*] Creating target directory ${MNT_POINT}${lMOUNT_PT}"
        mkdir -p "${MNT_POINT}""${lMOUNT_PT}"
      fi
      print_output "[*] Let's copy the identified area to the root filesystem - ${ORANGE}${lN_PATH}${NC} to ${ORANGE}${MNT_POINT}${lMOUNT_PT}${NC}"
      cp -pr --update=none "${lN_PATH}"* "${MNT_POINT}""${lMOUNT_PT}"
      find "${MNT_POINT}""${lMOUNT_PT}" -xdev -ls || true
    done

    print_output "[*] Final copy of ${ORANGE}${lFS_FIND}${NC} to ${ORANGE}${MNT_POINT}${lMOUNT_PT}${NC} ..."
    cp -pr --update=none "${lFS_FIND}"/* "${MNT_POINT}""${lMOUNT_PT}" || true
    # find "$MNT_POINT""$lMOUNT_PT" -xdev -ls || true
    ls -lh "${MNT_POINT}""${lMOUNT_PT}" || true
  done

  # now we need to startup the inferFile/inferService script again
  cp "$(command -v bash-static)" "${MNT_POINT}" || true
  cp "$(command -v busybox)" "${MNT_POINT}" || true
  cp "${MODULE_SUB_PATH}/inferService.sh" "${MNT_POINT}" || true
  print_output "[*] inferService.sh (chroot)"
  EMBA_BOOT=${EMBA_BOOT} EMBA_ETC=${EMBA_ETC} timeout --preserve-status --signal SIGINT 120 chroot "${MNT_POINT}" /bash-static /inferService.sh | tee -a "${LOG_FILE}"
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

cleanup_emulator() {
  local lIMAGE_NAME="${1:-}"
  if [[ -v ARCHIVE_PATH ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
    reset_network_emulation "${lIMAGE_NAME}" 1
  else
    reset_network_emulation "${lIMAGE_NAME}" 2
  fi

  # ugly cleanup:
  rm -rf /tmp/qemu."${lIMAGE_NAME}" 2>/dev/null || true
  rm -rf /tmp/qemu."${lIMAGE_NAME}".S1 2>/dev/null || true
  if [[ -f /tmp/do_not_create_run.sh ]]; then
    rm /tmp/do_not_create_run.sh || true
  fi

  # losetup
  losetup -D
}

delete_device_entry() {
  local lIMAGE_NAME="${1:-}"
  local lDEVICE="${2:-}"
  local lMNT_POINT="${3:-}"

  print_output "[*] Deleting device mapper for ${lIMAGE_NAME} / ${lDEVICE}" "no_log"

  kpartx -v -d "${LOG_PATH_MODULE}/${lIMAGE_NAME}"
  losetup -d "${lDEVICE}" &>/dev/null || true
  # just in case we check the output and remove our device:
  if losetup | grep -q "$(basename "${lIMAGE_NAME}")"; then
    losetup -d "$(losetup | grep "$(basename "${lIMAGE_NAME}")" | awk '{print $1}' || true)"
  fi
  dmsetup remove "$(basename "${lDEVICE}")" &>/dev/null || true
  rm -rf "${lMNT_POINT:?}/"* || true
  sleep 1
}

identify_networking_emulation() {
  # based on the original firmadyne and FirmAE script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/inferNetwork.sh

  local lIMAGE_NAME="${1:-}"
  export IMAGE=""
  IMAGE=$(abs_path "${LOG_PATH_MODULE}/${lIMAGE_NAME}")

  local lARCH_END="${2:-}"
  local lINIT_FILE="${3:-}"

  sub_module_title "Network identification ${lINIT_FILE} - ${KINIT} - ${lARCH_END} - ${lIMAGE_NAME}"

  print_output "[*] Test basic emulation and identify network settings.\\n"
  print_output "[*] Running firmware ${ORANGE}${lIMAGE_NAME}${NC}: Terminating after 660 secs..."

  local lCPU=""
  local lKERNEL=""
  local lQEMU_BIN=""
  local lQEMU_MACHINE=""
  local lQEMU_DISK=""
  local lQEMU_PARAMS=""
  local lQEMU_NETWORK=""
  local lQEMU_ROOTFS=""
  local lCONSOLE="ttyS0"

  lKERNEL="vmlinux"
  lQEMU_ROOTFS="/dev/sda1"
  lQEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
  # default network configuration with e1000 interface:
  lQEMU_NETWORK="-netdev socket,id=net0,listen=:2000 -device e1000,netdev=net0"
  lQEMU_NETWORK+=" -netdev socket,id=net1,listen=:2001 -device e1000,netdev=net1"
  lQEMU_NETWORK+=" -netdev socket,id=net2,listen=:2002 -device e1000,netdev=net2"
  lQEMU_NETWORK+=" -netdev socket,id=net3,listen=:2003 -device e1000,netdev=net3"

  if [[ "${lARCH_END}" == "mipsel" ]]; then
    lQEMU_BIN="qemu-system-${lARCH_END}"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64r2el" ]]; then
    lQEMU_BIN="qemu-system-mips64el"
    lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mipseb" ]]; then
    lQEMU_BIN="qemu-system-mips"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64r2eb" ]]; then
    lQEMU_BIN="qemu-system-mips64"
    lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64v1eb" ]]; then
    lQEMU_BIN="qemu-system-mips64"
    # lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64v1el" ]]; then
    lQEMU_BIN="qemu-system-mips64el"
    # lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64n32eb" ]]; then
    lQEMU_BIN="qemu-system-mips64"
    lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "armel"* ]]; then
    lKERNEL="zImage"
    lQEMU_BIN="qemu-system-arm"
    lQEMU_MACHINE="virt"
    lQEMU_DISK="-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    lQEMU_ROOTFS="/dev/vda1"
    lQEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev socket,listen=:2000,id=net0"
    # lQEMU_NETWORK+=" -device virtio-net-device,netdev=net1 -netdev socket,listen=:2001,id=net1"
    # lQEMU_NETWORK+=" -device virtio-net-device,netdev=net2 -netdev socket,listen=:2002,id=net2"
    # lQEMU_NETWORK+=" -device virtio-net-device,netdev=net3 -netdev socket,listen=:2003,id=net3"
  elif [[ "${lARCH_END}" == "arm64el"* ]]; then
    lKERNEL="Image"
    lQEMU_BIN="qemu-system-aarch64"
    lQEMU_MACHINE="virt"
    lCPU="-cpu cortex-a57"
    # lCONSOLE="ttyAMA0"
    lQEMU_DISK="-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    lQEMU_ROOTFS="/dev/vda1"
    lQEMU_NETWORK="-device virtio-net-device,netdev=net0 -netdev socket,listen=:2000,id=net0"
    # lQEMU_NETWORK+=" -device virtio-net-device,netdev=net1 -netdev socket,listen=:2001,id=net1"
    # lQEMU_NETWORK+=" -device virtio-net-device,netdev=net2 -netdev socket,listen=:2002,id=net2"
    # lQEMU_NETWORK+=" -device virtio-net-device,netdev=net3 -netdev socket,listen=:2003,id=net3"
  elif [[ "${lARCH_END}" == "x86el"* ]]; then
    lKERNEL="bzImage"
    # lKERNEL="vmlinux"
    lQEMU_BIN="qemu-system-x86_64"
    # lQEMU_BIN="qemu-system-i386"
    # lQEMU_MACHINE="pc-i440fx-3.1"
    lQEMU_MACHINE="pc-i440fx-8.2"
  elif [[ "${lARCH_END}" == "nios2el" ]]; then
    # not implemented -> Future
    lQEMU_BIN="qemu-system-nios2"
    lQEMU_MACHINE="10m50-ghrd"
    lQEMU_DISK="-drive file=${IMAGE},format=raw"
    lQEMU_NETWORK=""
  else
    print_output "[-] WARNING: No supported configuration found for ${ORANGE}${lARCH_END}${NC}."
    return
  fi

  run_network_id_emulation "${lCONSOLE}" "${lCPU}" "${lKERNEL}" "${lQEMU_BIN}" "${lQEMU_MACHINE}" "${lQEMU_DISK}" "${lQEMU_PARAMS}" "${lQEMU_NETWORK}" "${lQEMU_ROOTFS}" "${lIMAGE_NAME}" "${lINIT_FILE}" "${lARCH_END}" &

  local lPID="$!"
  disown "${lPID}" 2> /dev/null || true

  print_keepalive "${LOG_PATH_MODULE}/qemu.initial.serial.log" "${lIMAGE_NAME}" &
  local lALIVE_PID="$!"
  disown "${lALIVE_PID}" 2> /dev/null || true

  timeout --preserve-status --signal SIGINT 660 tail -F "${LOG_PATH_MODULE}/qemu.initial.serial.log" 2>/dev/null | grep -a -v "klogd" || true
  local lPID="$!"
  disown "${lPID}" 2> /dev/null || true

  kill "${lALIVE_PID}"
  print_output "[*] Call to stop emulation process - Source ${FUNCNAME[0]}" "no_log"
  stopping_emulation_process "${lIMAGE_NAME}"
  cleanup_emulator "${lIMAGE_NAME}"

  if ! [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
    print_output "[-] No ${ORANGE}${LOG_PATH_MODULE}/qemu.initial.serial.log${NC} log file generated."
  fi
}

print_keepalive() {
  # needed for run_kpanic_identification which we are calling from the keepalive printer
  local lLOG_FILE="${1:-}"
  local lIMAGE_NAME="${2:-}"

  # we give the whole system a few seconds until we start printing the keepalives
  # and also check for kernel panics
  sleep 10
  while(true); do
    print_output "[*] $(date) - EMBA emulation engine is live" "no_log"
    run_kpanic_identification_single "${lLOG_FILE}" "${lIMAGE_NAME}"
    sleep 5
  done
}

run_kpanic_identification_single() {
  local lLOG_FILE="${1:-}"
  local lIMAGE_NAME="${2:-}"

  lKPANIC=$(tail -n 20 "${lLOG_FILE}" | grep -a -c "Kernel panic - " || true)
  if [[ "${lKPANIC}" -gt 0 ]]; then
    print_output "[*] Kernel Panic detected - stopping emulation"
    tail -n 20 "${lLOG_FILE}" | grep -a "Kernel panic - " | tee -a "${LOG_FILE}"
    print_output "[*] Call to stop emulation process - Source ${FUNCNAME[0]}" "no_log"
    stopping_emulation_process "${lIMAGE_NAME}"
    pkill -9 -f tail.*-F.*"${lLOG_FILE}" &>/dev/null || true
  fi
}

#  run_network_id_emulation "${lCONSOLE}" "${lCPU}" "${lKERNEL}" "${lQEMU_BIN}" "${lQEMU_MACHINE}" "${lQEMU_DISK}" "${lQEMU_PARAMS}" "${lQEMU_NETWORK}" "${lQEMU_ROOTFS}" "${lIMAGE_NAME}" &
run_network_id_emulation() {
  local lCONSOLE="${1:-}"
  local lCPU="${2:-}"
  local lKERNEL="${3:-}"
  local lQEMU_BIN="${4:-}"
  local lQEMU_MACHINE="${5:-}"
  local lQEMU_DISK="${6:-}"
  local lQEMU_PARAMS="${7:-}"
  local lQEMU_NETWORK="${8:-}"
  local lQEMU_ROOTFS="${9:-}"
  local lIMAGE_NAME="${10:-}"
  local lINIT_FILE="${11:-}"
  local lARCH_END="${12:-}"

  print_output "[*] Qemu network identification run for ${ORANGE}${lARCH_END}${NC} - ${ORANGE}${lIMAGE_NAME}${NC}"

  # temp code for future use - currently only kernel v4 is supported
  if [[ "${lARCH_END}" == *"mips"* ]]; then
    export KERNEL_V=""
    get_kernel_version
    if [[ -n "${KERNEL_V}" ]]; then
      print_output "[*] Kernel ${KERNEL_V}.x detected -> Using Kernel v4.x"
      KERNEL_V=".${KERNEL_V}"
    else
      KERNEL_V=".4"
    fi
    # hard code v4.x
    KERNEL_V=".4"
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/${lKERNEL}.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/${lKERNEL}.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
  elif [[ "${lARCH_END}" == *"x86el"* ]] && [[ "${L10_KERNEL_V_LONG}" == "4.1.52" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v4.1.17/${lKERNEL}.${lARCH_END}" ]]; then
      # x86el kernel has issues in version 4.1.52 - need further investigation
      print_output "[!] Bypassing known issues with kernel v${L10_KERNEL_V_LONG} - switching to v4.1.17"
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v4.1.17/${lKERNEL}.${lARCH_END}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
  else
    # ARM/x86 architecture
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/${lKERNEL}.${lARCH_END}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/${lKERNEL}.${lARCH_END}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
  fi

  check_qemu_instance_l10

  print_output "[*] Qemu parameters used in network detection mode:"
  print_output "$(indent "MACHINE: ${ORANGE}${lQEMU_MACHINE}${NC}")"
  print_output "$(indent "KERNEL: ${ORANGE}${lKERNEL}${NC}")"
  print_output "$(indent "DRIVE: ${ORANGE}${lQEMU_DISK}${NC}")"
  print_output "$(indent "KINIT: ${ORANGE}${KINIT}${NC}")"
  print_output "$(indent "ROOT_DEV: ${ORANGE}${lQEMU_ROOTFS}${NC}")"
  print_output "$(indent "QEMU binary: ${ORANGE}${lQEMU_BIN}${NC}")"
  print_output "$(indent "NETWORK: ${ORANGE}${lQEMU_NETWORK}${NC}")"
  print_output "$(indent "Init file: ${ORANGE}${lINIT_FILE}${NC}")"
  print_output "$(indent "Console interface: ${ORANGE}${lCONSOLE}${NC}")"
  print_ln
  print_output "[*] Starting firmware emulation for network identification - ${ORANGE}${lQEMU_BIN} / ${lARCH_END} / ${lIMAGE_NAME}${NC} ... use Ctrl-a + x to exit"
  print_ln

  # timeout ensures we are able to end this somewhere in the future - just in case something goes wrong
  write_script_exec "timeout --preserve-status --signal SIGINT 6000 ${lQEMU_BIN} -m 2048 -M ${lQEMU_MACHINE} ${lCPU} -kernel ${lKERNEL} ${lQEMU_DISK} -append \"root=${lQEMU_ROOTFS} console=${lCONSOLE} nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${KINIT} rw debug ignore_loglevel print-fatal-signals=1 EMBA_NET=${EMBA_NET} EMBA_NVRAM=${EMBA_NVRAM} EMBA_KERNEL=${EMBA_KERNEL} EMBA_ETC=${EMBA_ETC} user_debug=0 firmadyne.syscall=1\" -nographic ${lQEMU_NETWORK} ${lQEMU_PARAMS} -serial file:${LOG_PATH_MODULE}/qemu.initial.serial.log -serial telnet:localhost:4321,server,nowait -serial unix:/tmp/qemu.${lIMAGE_NAME}.S1,server,nowait -monitor unix:/tmp/qemu.${lIMAGE_NAME},server,nowait ; pkill -9 -f tail.*-F.*\"${LOG_PATH_MODULE}\"" /tmp/do_not_create_run.sh 2
}

get_networking_details_emulation() {
  IMAGE_NAME="${1:-}"

  sub_module_title "Network identification - ${IMAGE_NAME}"
  export PANICS=()
  export DETECTED_IP=0
  export MISSING_FILES=()

  if [[ -f "${LOG_PATH_MODULE}"/qemu.initial.serial.log ]]; then
    local lETH_INT="NONE"
    local lVLAN_ID="NONE"
    local lNETWORK_MODE="bridge"
    local lNETWORK_DEVICE=""

    export NVRAMS=()
    export TCP_SERVICES_STARTUP=()
    export UDP_SERVICES_STARTUP=()

    local lNVRAM_ARR=()
    local lNVRAM_TMP=()
    local lNVRAM_ENTRY=""
    local lBRIDGE_INTERFACES=()
    local lBRIDGE_INT=""
    local lINTERFACE_CANDIDATES=()
    local lINTERFACE_CAND=""
    local lVLAN_INFOS=()
    local lVLAN_INFO=""
    local lVLAN_HW_INFO_DEV=()
    local lPORTS_ARR=()
    local lPORT=""
    local l_NW_ENTRY_PRIO=1
    local lADJUST_PRIO=0  # adjust priority

    local lTCP_PORT=""
    local lUDP_PORT=""
    local lMISSING_FILES_TMP=()
    local lMISSING_DIRS_TMP=()
    local lSERVICE_NAME=""

    mapfile -t lINTERFACE_CANDIDATES < <(grep -a "__inet_insert_ifa" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | cut -d: -f2- | sed -E 's/.*__inet_insert_ifa\[PID:\ [0-9]+\ //' \
     | sort -u | grep -v "device:lo ifa:0x0100007f" | grep -v -E " = -[0-9][0-9]" | sed 's/\[.*\]\ EMBA.*//' || true)
    mapfile -t lBRIDGE_INTERFACES < <(grep -a "br_add_if\|br_dev_ioctl" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | cut -d: -f4- | sort -u || true)
                #               br_add_if[PID: 246 (brctl)]: br:br0 dev:vlan1
    mapfile -t lVLAN_INFOS < <(grep -a "register_vlan_dev" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | cut -d: -f2- | sort -u | grep -v -E " = -[0-9][0-9]" || true)
    # mapfile -t PANICS < <(grep -a "Kernel panic - " "${LOG_PATH_MODULE}"/qemu.initial.serial.log | sort -u || true)
    # # ensure we only stop if we have a panic near the end - otherwise the system probably has rebooted and recovered
    mapfile -t PANICS < <(tail -n 50 "${LOG_PATH_MODULE}"/qemu.initial.serial.log | grep -a "Kernel panic - " | sort -u || true)
    mapfile -t lNVRAM_ARR < <(grep -a "\[NVRAM\] " "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk '{print $3}' | grep -a -E '[[:alnum:]]{3,50}' | sort -u || true)
    # we check all available qemu logs for services that are started:
    mapfile -t lPORTS_ARR < <(grep -a "inet_bind" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | sed -E 's/.*inet_bind\[PID:\ [0-9]+\ //' | sort -u || true)
    mapfile -t lVLAN_HW_INFO_DEV < <(grep -a -E "adding VLAN [0-9] to HW filter on device eth[0-9]" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk -F\  '{print $NF}' | sort -u || true)

    # we handle missing files in setup_network_config -> there we already remount the filesystem and we can perform the changes
    mapfile -t lMISSING_FILES_TMP < <(grep -a -E "No such file or directory" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | tr ' ' '\n' | grep -a "/" | grep -a -v proc | tr -d ':' | tr -d "'" | tr -d '`' | sort -u || true)
    MISSING_FILES+=( "${lMISSING_FILES_TMP[@]}" )
    mapfile -t lMISSING_DIRS_TMP < <(grep -a -E "nonexistent directory" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | tr ' ' '\n' | grep -a "/" | grep -a -v proc | tr -d ':' | tr -d "'" | tr -d '`' | grep -a "^/" | sort -u || true)
    MISSING_FILES+=( "${lMISSING_DIRS_TMP[@]}" )

    lNVRAM_TMP=( "${lNVRAM_ARR[@]}" )

    if [[ "${#lINTERFACE_CANDIDATES[@]}" -gt 0 || "${#lBRIDGE_INTERFACES[@]}" -gt 0 || "${#lVLAN_INFOS[@]}" -gt 0 || "${#lPORTS_ARR[@]}" -gt 0 || "${#lNVRAM_TMP[@]}" -gt 0 ]]; then
      print_output "[+] Booted system detected."
      BOOTED="yes"
    fi

    if [[ -v lNVRAM_TMP[@] ]]; then
      for lNVRAM_ENTRY in "${lNVRAM_TMP[@]}"; do
        if [[ "${lNVRAM_ENTRY}" =~ [[:print:]] ]]; then
          if [[ ! " ${NVRAMS[*]} " =~  ${lNVRAM_ENTRY}  ]]; then
            NVRAMS+=( "${lNVRAM_ENTRY}" )
          fi
        fi
      done
      print_output "[*] NVRAM access detected ${ORANGE}${#NVRAMS[@]}${NC} times."
      print_ln
    fi

    if [[ -v lPORTS_ARR[@] ]]; then
      for lPORT in "${lPORTS_ARR[@]}"; do
        lSERVICE_NAME=$(strip_color_codes "$(echo "${lPORT}" | sed -e 's/.*\((.*)\).*/\1/g' | tr -d "(" | tr -d ")")")
        lSERVICE_NAME="${lSERVICE_NAME//[![:print:]]/}"
        lTCP_PORT=$(strip_color_codes "$(echo "${lPORT}" | grep "SOCK_STREAM" | sed 's/.*SOCK_STREAM,\ //' | sort -u | cut -d: -f2)" || true)
        lTCP_PORT="${lTCP_PORT//[![:print:]]/}"
        lUDP_PORT=$(strip_color_codes "$(echo "${lPORT}" | grep "SOCK_DGRAM" | sed 's/.*SOCK_DGRAM,\ //' | sort -u | cut -d: -f2)" || true)
        lUDP_PORT="${lUDP_PORT//[![:print:]]/}"

        if [[ "${lTCP_PORT}" =~ [0-9]+ ]]; then
          print_output "[*] Detected TCP service startup: ${ORANGE}${lSERVICE_NAME}${NC} / ${ORANGE}${lTCP_PORT}${NC}"
          TCP_SERVICES_STARTUP+=( "${lTCP_PORT}" )
        fi
        if [[ "${lUDP_PORT}" =~ [0-9]+ ]]; then
          print_output "[*] Detected UDP service startup: ${ORANGE}${lSERVICE_NAME}${NC} / ${ORANGE}${lUDP_PORT}${NC}"
          UDP_SERVICES_STARTUP+=( "${lUDP_PORT}" )
        fi

        SERVICES_STARTUP+=( "${lSERVICE_NAME}" )
      done
    fi

    mapfile -t SERVICES_STARTUP < <(printf "%s\n" "${SERVICES_STARTUP[@]}" | sort -u)
    mapfile -t UDP_SERVICES_STARTUP < <(printf "%s\n" "${UDP_SERVICES_STARTUP[@]}" | sort -u)
    mapfile -t TCP_SERVICES_STARTUP < <(printf "%s\n" "${TCP_SERVICES_STARTUP[@]}" | sort -u)

    for lVLAN_INFO in "${lVLAN_INFOS[@]}"; do
      # register_vlan_dev[PID: 128 (vconfig)]: dev:eth1.1 vlan_id:1
      print_output "[*] Possible VLAN details detected: ${ORANGE}${lVLAN_INFO}${NC}"
    done

    if [[ -v lBRIDGE_INTERFACES[@] ]]; then
      mapfile -t lBRIDGE_INTERFACES < <(printf "%s\n" "${lBRIDGE_INTERFACES[@]}" | sort -u)
      print_ln
    fi

    for lINTERFACE_CAND in "${lINTERFACE_CANDIDATES[@]}"; do
      lINTERFACE_CAND="${lINTERFACE_CAND//[![:print:]]/}"
      print_output "[*] Possible interface candidate detected: ${ORANGE}${lINTERFACE_CAND}${NC}"
      # lINTERFACE_CAND -> __inet_insert_ifa[PID: 139 (ifconfig)]: device:br0 ifa:0xc0a80001
      local lIP_ADDRESS_HEX=()
      local lIP_CAND=""
      lIP_CAND=$(echo "${lINTERFACE_CAND}" | tr ' ' '\n' | grep ifa | cut -d: -f2 | sed 's/0x//')
      # shellcheck disable=SC2001
      mapfile -t lIP_ADDRESS_HEX < <(echo "${lIP_CAND:0:8}" | sed 's/../0x&\n/g')
      # lIP_ADDRESS_HEX -> c0a80001
      # as I don't get it to change the hex ip to dec with printf, we do it the poor way:
      local lIP=""
      local lCNT=0
      for _IPs in "${lIP_ADDRESS_HEX[@]}"; do
        lCNT=$((lCNT+1))
        if [[ "${_IPs}" == "0x"* ]]; then
          # shellcheck disable=SC2004
          lIP="${lIP}.$((${_IPs}))"
        fi
        # ensure we only check a valid ip address - this is needed if our IP address extraction gets mangled data:
        [[ "${lCNT}" -ge 4 ]] && break
      done

      lIP="${lIP/\.}"

      IP_ADDRESS_=""
      if [[ "${D_END,,}" == "eb" ]]; then
        IP_ADDRESS_="${lIP}"
      elif [[ "${D_END,,}" == "el" ]]; then
        IP_ADDRESS_=$(echo "${lIP}" | tr '.' '\n' | tac | tr '\n' '.' | sed 's/\.$//')
      fi

      # handle IP addresses 0.0.0.0 somehow:
      if [[ "${IP_ADDRESS_}" == "0.0.0.0" ]]; then
        local lADJUST_PRIO+=-1
        # we use one of the idenfied IP addresses. If no IP address available we switch to default 192.168.0.1
        if [[ -s "${L10_SYS_EMU_RESULTS}" ]]; then
          IP_ADDRESS_=$(cut -d\; -f8 "${L10_SYS_EMU_RESULTS}" | sort -u | tail -n1)
          IP_ADDRESS_="${IP_ADDRESS_/*\ /}"
          print_output "[*] Originally identified IP 0.0.0.0 -> using backup IP ${IP_ADDRESS_}"
        else
          IP_ADDRESS_="192.168.0.1"
          print_output "[*] Originally identified IP 0.0.0.0 -> using default IP ${IP_ADDRESS_}"
        fi
      fi

      # filter for non usable IP addresses:
      if [[ "${IP_ADDRESS_}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && ! [[ "${IP_ADDRESS_}" == "127."* ]]; then
        print_output "[*] Identified IP address: ${ORANGE}${IP_ADDRESS_}${NC} / ${ORANGE}${lINTERFACE_CAND}${NC}"
        DETECTED_IP=1
        # get the network device from our interface candidate
        lNETWORK_DEVICE="$(echo "${lINTERFACE_CAND}" | grep device | cut -d: -f2- | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2 || true)"
        # lINTERFACE_CAND -> __inet_insert_ifa[PID: 139 (ifconfig)]: device:br0 ifa:0xc0a80001
        #                   __inet_insert_ifa[PID: 899 (udhcpc)]: device:eth0 ifa:0xbea48f41
        # lNETWORK_DEVICE -> eth0, eth1.1, br0 ...

        if [[ -n "${lNETWORK_DEVICE}" ]]; then
          # if the network device is not a eth it is a bridge interface
          # if we have lBRIDGE_INTERFACES we also check it here (this way we can correct the br interface entry):
          if [[ "${lNETWORK_DEVICE}" != *"eth"* ]] || [[ "${#lBRIDGE_INTERFACES[@]}" -gt 0 ]]; then
            print_output "[*] Possible br interface detected: ${ORANGE}${lNETWORK_DEVICE}${NC} / IP: ${ORANGE}${IP_ADDRESS_}${NC}"
            lNETWORK_MODE="bridge"
            if [[ "${#lBRIDGE_INTERFACES[@]}" -gt 0 ]]; then
              for lBRIDGE_INT in "${lBRIDGE_INTERFACES[@]}"; do
                # lBRIDGE_INT -> br_add_if[PID: 494 (brctl)]: br:br0 dev:eth0.1
                #               br_add_if[PID: 246 (brctl)]: br:br0 dev:vlan1
                # lNETWORK_DEVICE -> br0
                lBRIDGE_INT="${lBRIDGE_INT//[![:print:]]/}"
                print_output "[*] Testing bridge interface: ${ORANGE}${lBRIDGE_INT}${NC}" "no_log"
                lVLAN_ID="NONE"
                # the lBRIDGE_INT entry also includes our lNETWORK_DEVICE ... eg br:br0 dev:eth1.1
                l_NW_ENTRY_PRIO=$((3+lADJUST_PRIO))
                if [[ "${lBRIDGE_INT}" == *"${lNETWORK_DEVICE}"* ]]; then
                  # matching is quite good. This means that the bridge entry (br_add_if[PID: 494 (brctl)]: br:br0 dev:eth0)
                  # is matching our interface candidate entry (__inet_insert_ifa[PID: 139 (ifconfig)]: device:eth0 ifa:0xc0a80001)
                  # Nevertheless, we also need to process non matching results where we have network entries without a matching
                  # bridge interface
                  print_output "[+] Processing matching bridge interface: ${ORANGE}${lBRIDGE_INT}${GREEN} / network device: ${ORANGE}${lNETWORK_DEVICE}${NC}"
                else
                  print_output "[*] Processing NON matching bridge interface: ${ORANGE}${lBRIDGE_INT}${NC} / network device: ${ORANGE}${lNETWORK_DEVICE}${NC}"
                fi
                # br_add_if[PID: 138 (brctl)]: br:br0 dev:eth1.1
                # extract the eth1 from dev:eth1
                lETH_INT="$(echo "${lBRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f1 | cut -d: -f2)"
                lETH_INT="${lETH_INT//[![:print:]]/}"
                # do we have vlans?
                if [[ -v lVLAN_INFOS[@] ]]; then
                  iterate_vlans "${lETH_INT}" "${lNETWORK_MODE}" "${lNETWORK_DEVICE}" "${IP_ADDRESS_}" "${lVLAN_INFOS[@]}"
                fi
                if echo "${lBRIDGE_INT}" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]"; then
                  # we have a vlan entry in our lBRIDGE_INT entry br:br0 dev:eth1.1:
                  lVLAN_ID="$(echo "${lBRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f2)"
                  lVLAN_ID="${lVLAN_ID//[![:print:]]/}"
                fi
                if [[ -v lVLAN_HW_INFO_DEV[@] ]]; then
                  # lets store the current details before we do this VLAN iteration
                  store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
                  # if we have found some entry "adding VLAN [0-9] to HW filter on device ethX" in our qemu logs
                  # we check all these entries now and generate additional configurations for further evaluation
                  for lETH_INT in "${lVLAN_HW_INFO_DEV[@]}"; do
                    # if we found multiple interfaces belonging to a vlan we need to store all of them:
                    lETH_INT="${lETH_INT//[![:print:]]/}"
                    lVLAN_ID=$(grep -a -o -E "adding VLAN [0-9] to HW filter on device ${lETH_INT}" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk '{print $3}' | sort -u)
                    # initial entry with possible vlan information
                    l_NW_ENTRY_PRIO=$((5+lADJUST_PRIO))
                    store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"

                    # entry with vlan NONE (just in case as backup)
                    l_NW_ENTRY_PRIO=$((4+lADJUST_PRIO))
                    store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "NONE" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"

                    if ! [[ "${lNETWORK_DEVICE}" == *br[0-9]* ]] && ! [[ "${lNETWORK_DEVICE}" == *eth[0-9]* ]]; then
                      # entry with vlan NONE and interface br0 - just as another fallback solution
                      local lNETWORK_DEVICE="br0"
                      print_output "[*] Fallback bridge interface - #1 ${ORANGE}${lNETWORK_DEVICE}${NC}"
                      l_NW_ENTRY_PRIO=$((3+lADJUST_PRIO))
                      store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
                    fi
                  done
                fi
                # now we set the orig. network_device with the new details (lVLAN_ID=NONE):
                store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"

                if ! [[ "${lNETWORK_DEVICE}" == *br[0-9]* ]] && ! [[ "${lNETWORK_DEVICE}" == *eth[0-9]* ]]; then
                  # if we have a bridge device like br-lan we ensure we also have an entry with a usual br0 interface
                  local lNETWORK_DEVICE="br0"
                  print_output "[*] Fallback bridge interface - #2 ${ORANGE}${lNETWORK_DEVICE}${NC}"
                  l_NW_ENTRY_PRIO=$((3+lADJUST_PRIO))
                  store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
                fi
                # if we have found that the br entry has for eg an ethX interface, we now check for the real br interface entry -> lNETWORK_DEVICE
                lNETWORK_DEVICE="$(echo "${lBRIDGE_INT}" | grep -o "br:.*" | cut -d\  -f1 | cut -d: -f2)"
                lNETWORK_DEVICE="${lETH_INT//[![:print:]]/}"
                l_NW_ENTRY_PRIO=$((4+lADJUST_PRIO))
                store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE:-br0}" "${lETH_INT:-eth0}" "${lVLAN_ID:-0}" "${lNETWORK_MODE:-bridge}" "${l_NW_ENTRY_PRIO}"
              done
            else
              # set typical default values - this is just in case we have not found br_add_if entries:
              lVLAN_ID="NONE"
              l_NW_ENTRY_PRIO=$((3+lADJUST_PRIO))
              if [[ "$(grep -ac "eth0" "${LOG_PATH_MODULE}"/qemu.initial.serial.log)" -gt 0 ]]; then
                lETH_INT="eth0"
                store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
              fi
              if [[ "$(grep -ac "eth1" "${LOG_PATH_MODULE}"/qemu.initial.serial.log)" -gt 0 ]]; then
                lETH_INT="eth1"
                store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
              fi
            fi
          elif [[ "${lNETWORK_DEVICE}" == *"eth"* ]]; then
            print_output "[*] Possible eth network interface detected: ${ORANGE}${lNETWORK_DEVICE}${GREEN} / IP: ${ORANGE}${IP_ADDRESS_}${NC}"
            lNETWORK_MODE="normal"
            if echo "${lNETWORK_DEVICE}" | grep -q -E "[0-9]\.[0-9]"; then
              # now we know that there is a vlan number - extract the vlan number now:
              l_NW_ENTRY_PRIO=$((4+lADJUST_PRIO))
              lVLAN_ID="$(echo "${lNETWORK_DEVICE}" | cut -d. -f2 | grep -E "[0-9]+")"
              lVLAN_ID="${lVLAN_ID//[![:print:]]/}"
            elif [[ -v lVLAN_INFOS[@] ]]; then
              lETH_INT="${lNETWORK_DEVICE/\.*}"
              iterate_vlans "${lETH_INT}" "${lNETWORK_MODE}" "${lNETWORK_DEVICE}" "${IP_ADDRESS_}" "${lVLAN_INFOS[@]}"
            else
              l_NW_ENTRY_PRIO=$((3+lADJUST_PRIO))
              lVLAN_ID="NONE"
            fi
            lNETWORK_DEVICE="${lNETWORK_DEVICE/\.*}"
            lETH_INT="${lNETWORK_DEVICE/\.*}"
            store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
          else
            # could not happen - just for future extension
            print_output "[+] Possible other interface detected: ${ORANGE}${lNETWORK_DEVICE}${NC}"
            lVLAN_ID="NONE"
            lNETWORK_MODE="normal"
            lNETWORK_DEVICE="${lNETWORK_DEVICE/\.*}"
            lETH_INT="${lNETWORK_DEVICE}"
            l_NW_ENTRY_PRIO=1
            store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
          fi
        fi
        # this is a default (fallback) entry with the correct ip address:
        l_NW_ENTRY_PRIO=$((2+lADJUST_PRIO))
        store_interface_details "${IP_ADDRESS_}" "br0" "eth0" "NONE" "default" "${l_NW_ENTRY_PRIO}"
        # this is a default (fallback) entry with the correct ip address:
        l_NW_ENTRY_PRIO=1
        store_interface_details "${IP_ADDRESS_}" "eth0" "eth0" "NONE" "interface" "${l_NW_ENTRY_PRIO}"
      fi
    done

    # this is for testing. Probably we can improve it in the future to have a better fallback handling
    if [[ "${L10_DEBUG_MODE}" -eq 2 ]]; then
      if [[ "${#lINTERFACE_CANDIDATES[@]}" -eq 0 ]] || [[ "${L10_DEBUG_MODE}" -eq 2 ]]; then
        # in this case we do not have valid ip addresses
        # this mechanism is very alpha and just as fallback mechanism designed
        # we need to further improve this mechanism to include VLAN detection, bridge vs interface vs normal ...
        local lIP_ADDR_BACKUP_ARR=()
        local lIP_ADDR_BACKUP=""
        mapfile -t lIP_ADDR_BACKUP_ARR < <(grep -h "ip.*addr" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | grep -o -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
          | grep -E -v "\.255$" | grep -v -E "\.0$" | grep -v -E "^127\." | grep -v "^255\." | sort -u || true)
        for lIP_ADDR_BACKUP in "${lIP_ADDR_BACKUP_ARR[@]}"; do
          # if we have bridge interfaces found and we have some eth0 entries in our qemu log we guess a shiny configuration
          if [[ -v lBRIDGE_INTERFACES[@] ]]; then
            if [[ "$(grep -ac "eth0" "${LOG_PATH_MODULE}"/qemu.initial.serial.log)" -gt 0 ]]; then
              l_NW_ENTRY_PRIO=$((2+lADJUST_PRIO))
              store_interface_details "${lIP_ADDR_BACKUP}" "br0" "eth0" "NONE" "bridge" "${l_NW_ENTRY_PRIO}"
              store_interface_details "${lIP_ADDR_BACKUP}" "br0" "eth0" "0" "bridge" "${l_NW_ENTRY_PRIO}"
            fi
          fi
          l_NW_ENTRY_PRIO=1
          if [[ "$(grep -ac "eth0" "${LOG_PATH_MODULE}"/qemu.initial.serial.log)" -gt 0 ]]; then
            store_interface_details "${lIP_ADDR_BACKUP}" "eth0" "eth0" "NONE" "interface" "${l_NW_ENTRY_PRIO}"
            store_interface_details "${lIP_ADDR_BACKUP}" "br0" "eth0" "NONE" "default" "${l_NW_ENTRY_PRIO}"
          fi
          if [[ "$(grep -ac "eth1" "${LOG_PATH_MODULE}"/qemu.initial.serial.log)" -gt 0 ]]; then
            store_interface_details "${lIP_ADDR_BACKUP}" "eth1" "eth1" "NONE" "interface" "${l_NW_ENTRY_PRIO}"
            store_interface_details "${lIP_ADDR_BACKUP}" "br0" "eth1" "NONE" "default" "${l_NW_ENTRY_PRIO}"
          fi
        done
      fi
    fi

    if [[ "${#IPS_INT_VLAN[@]}" -eq 0 ]]; then
      # this section is if we have a brctl entry but no IP address
      for lBRIDGE_INT in "${lBRIDGE_INTERFACES[@]}"; do
        # br_add_if[PID: 138 (brctl)]: br:br0 dev:eth1.1
        # lBRIDGE_INT -> br_add_if[PID: 494 (brctl)]: br:br0 dev:eth0.1
        # lNETWORK_DEVICE -> br0
        print_output "[*] Possible bridge interface candidate detected: ${ORANGE}${lBRIDGE_INT}${NC}"
        lETH_INT="$(echo "${lBRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f1 | cut -d: -f2 || true)"
        lETH_INT="${lETH_INT//[![:print:]]/}"
        lNETWORK_DEVICE="$(echo "${lBRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "br:.*" | cut -d\  -f1 | cut -d: -f2 || true)"
        lNETWORK_DEVICE="${lNETWORK_DEVICE//[![:print:]]/}"
        IP_ADDRESS_="192.168.0.1"
        lNETWORK_MODE="bridge"
        if echo "${lBRIDGE_INT}" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]"; then
          # we have a vlan entry:
          # lVLAN_ID="$(echo "${lBRIDGE_INT}" | sed "s/^.*\]:\ //" | grep -o "dev:.*" | cut -d. -f2 | tr -dc '[:print:]' || true)"
          lVLAN_ID="$(echo "${lBRIDGE_INT}" | grep -o "dev:.*" | cut -d. -f2 || true)"
          lVLAN_ID="${lVLAN_ID//[![:print:]]/}"
        else
          lVLAN_ID="NONE"
          if [[ -v lVLAN_INFOS[@] ]]; then
            iterate_vlans "${lETH_INT}" "${lNETWORK_MODE}" "${lNETWORK_DEVICE}" "${IP_ADDRESS_}" "${lVLAN_INFOS[@]}"
          fi
        fi
        l_NW_ENTRY_PRIO=$((2+lADJUST_PRIO))
        store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
      done
    fi

    # fallback - default network configuration:
    # we always add this as the last resort - with this at least ICMP should be possible in most cases
    if [[ ! " ${IPS_INT_VLAN[*]} " =~ "normal" ]]; then
      # print_output "[*] No IP address - use default address: ${ORANGE}192.168.0.1${NC}."
      # print_output "[*] No VLAN."
      # print_output "[*] No Network interface - use ${ORANGE}eth0${NC} network."
      IP_ADDRESS_="192.168.0.1"
      lNETWORK_MODE="normal"
      l_NW_ENTRY_PRIO=1
      if [[ "${FW_VENDOR:-}" == "AVM" ]]; then
        # for AVM fritzboxen the default IP is set to the correct one:
        IP_ADDRESS_="192.168.178.1"
        l_NW_ENTRY_PRIO=$((2+lADJUST_PRIO))
      fi
      lVLAN_ID="NONE"
      lETH_INT="eth0"
      lNETWORK_DEVICE="br0"
      store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
    fi

    # fallback - default network configuration:
    # we always add this as the last resort - with this at least ICMP should be possible in most cases
    if [[ ! " ${IPS_INT_VLAN[*]} " =~ "default" ]]; then
      # print_output "[*] No IP address - use default address: ${ORANGE}192.168.0.1${NC}."
      # print_output "[*] No VLAN."
      # print_output "[*] No Network interface - use ${ORANGE}eth0${NC} network."
      IP_ADDRESS_="192.168.0.1"
      lNETWORK_MODE="default"
      l_NW_ENTRY_PRIO=1
      if [[ "${FW_VENDOR:-}" == "AVM" ]]; then
        # for AVM fritzboxen the default IP is set to the correct one:
        IP_ADDRESS_="192.168.178.1"
        l_NW_ENTRY_PRIO=$((2+lADJUST_PRIO))
      fi
      lVLAN_ID="NONE"
      lETH_INT="eth0"
      lNETWORK_DEVICE="br0"
      store_interface_details "${IP_ADDRESS_}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
    fi

    for PANIC in "${PANICS[@]}"; do
      print_output "[!] WARNING: Kernel Panic detected: ${ORANGE}${PANIC}${NC}"
      print_output "${NC}"
      PANICS=()
    done
    color_qemu_log "${LOG_PATH_MODULE}/qemu.initial.serial.log"
  else
    print_output "[-] No ${ORANGE}${LOG_PATH_MODULE}/qemu.initial.serial.log${NC} log file generated."
  fi
  print_ln
}

store_interface_details() {
  local lIP_ADDRESS="${1:-192.168.0.1}"
  local lNETWORK_DEVICE="${2:-br0}"
  local lETH_INT="${3:-eth0}"
  local lVLAN_ID="${4:-NONE}"
  local lNETWORK_MODE="${5:-bridge}"
  local lENTRY_PRIO="${6:-1}"

  print_output "[+] Interface details detected: IP address: ${ORANGE}${lIP_ADDRESS}${GREEN} / bridge dev: ${ORANGE}${lNETWORK_DEVICE}${GREEN} / network device: ${ORANGE}${lETH_INT}${GREEN} / vlan id: ${ORANGE}${lVLAN_ID}${GREEN} / network mode: ${ORANGE}${lNETWORK_MODE}${GREEN} / priority: ${ORANGE}${lENTRY_PRIO}${NC}"

  if [[ "${IPS_INT_VLAN[*]}" == *"${lIP_ADDRESS};${lNETWORK_DEVICE};${lETH_INT};${lVLAN_ID};${lNETWORK_MODE}"* ]]; then
    # we store it only if we do not have it in our array. Otherwise it is just printed for the logs
    return
  fi

  IPS_INT_VLAN+=( "${lENTRY_PRIO}"\;"${lIP_ADDRESS}"\;"${lNETWORK_DEVICE}"\;"${lETH_INT}"\;"${lVLAN_ID}"\;"${lNETWORK_MODE}" )
}

iterate_vlans() {
  local lETH_INT="${1:-}"
  local lNETWORK_MODE="${2:-}"
  local lNETWORK_DEVICE="${3:-}"
  local lIP_ADDRESS="${4:-}"
  shift 4
  local lVLAN_INFOS_ARR=("$@")

  local lETH_INT_=""
  local lETH_INTS_ARR=()
  local lVLAN_DEV=""
  local lVLAN_ID="NONE"
  local lVLAN_INFO=""

  for lVLAN_INFO in "${lVLAN_INFOS_ARR[@]}"; do
    print_output "[*] Analyzing VLAN details ${ORANGE}${lVLAN_INFO}${NC}"
    if ! [[ "${lVLAN_INFO}" == *"register_vlan_dev"* ]]; then
      continue
    fi
    # lVLAN_INFO -> register_vlan_dev[PID: 848 (vconfig)]: dev:eth2.1 vlan_id:1
    #              register_vlan_dev[PID: 213 (vconfig)]: dev:vlan1 vlan_id:1
    lVLAN_DEV=$(echo "${lVLAN_INFO}" | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2 | cut -d\. -f1)
    print_output "[*] VLAN details: ${ORANGE}${lVLAN_INFO}${NC}"
    print_output "[*] Interface details: ${ORANGE}${lETH_INT}${NC}"
    if [[ "${lVLAN_DEV}" == *"${lETH_INT}"* ]]; then
      print_output "[*] Possible matching VLAN details detected: ${ORANGE}${lVLAN_INFO}${NC}"
      l_NW_ENTRY_PRIO=5
      lVLAN_ID=$(echo "${lVLAN_INFO}" | sed "s/.*vlan_id://" | grep -E -o "[0-9]+" )
      lVLAN_ID="${lVLAN_ID//[![:print:]]/}"
    else
      l_NW_ENTRY_PRIO=2
      lVLAN_ID="NONE"
    fi
    store_interface_details "${lIP_ADDRESS}" "${lNETWORK_DEVICE}" "${lETH_INT}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"

    # check this later
    # store_interface_details "${lIP_ADDRESS}" "${lNETWORK_DEVICE}" "eth0" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
    # store_interface_details "${lIP_ADDRESS}" "${lNETWORK_DEVICE}" "eth0" "0" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
    # store_interface_details "${lIP_ADDRESS}" "${lNETWORK_DEVICE}" "eth1" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
    # store_interface_details "${lIP_ADDRESS}" "${lNETWORK_DEVICE}" "eth1" "0" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"

    # if we have entries without an interface name, we need to identify an interface name:
    # register_vlan_dev[PID: 212 (vconfig)]: dev:vlan1 vlan_id:1
    # for this we try to check the qemu output for vlan entries and generate the configuration entry
    if grep -a -q "adding VLAN [0-9] to HW filter on device eth[0-9]" "${LOG_PATH_MODULE}"/qemu.initial.serial.log; then
      mapfile -t lETH_INTS_ARR < <(grep -a -E "adding VLAN [0-9] to HW filter on device eth[0-9]" "${LOG_PATH_MODULE}"/qemu.initial.serial.log | awk -F\  '{print $NF}' | sort -u)
      for lETH_INT_ in "${lETH_INTS_ARR[@]}"; do
        # if we found multiple interfaces belonging to a vlan we need to store all of them:
        lETH_INT_="${lETH_INT_//[![:print:]]/}"
        l_NW_ENTRY_PRIO=4
        store_interface_details "${lIP_ADDRESS}" "${lNETWORK_DEVICE}" "${lETH_INT_}" "${lVLAN_ID}" "${lNETWORK_MODE}" "${l_NW_ENTRY_PRIO}"
      done
    fi
  done
}

setup_network_emulation() {
  local lIPS_INT_VLAN_CFG="${1:-}"

  local lIP_ADDRESS=""
  local lNETWORK_DEVICE=""
  local lETH_INT=""
  local lNETWORK_MODE=""
  local lTAP_ID=""
  local lHOSTIP=""
  local lVLAN_ID=""
  export BR_NUM=0
  export ETH_NUM=0

  sub_module_title "Setup networking - ${lIPS_INT_VLAN_CFG//\;/-}"

  # Source: IPS_INT_VLAN+=( "PRIO"-"${IP_ADDRESS_}"-"${lNETWORK_DEVICE}"-"${lETH_INT}"-"${lVLAN_ID}"-"${lNETWORK_MODE}" )
  lIP_ADDRESS=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f2)
  lNETWORK_DEVICE=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f3)
  lETH_INT=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f4)
  lVLAN_ID=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f5)
  lNETWORK_MODE=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f6)

  # a br interface with a number ... eg br0, br1 ... but no br-lan interface
  if [[ "${lNETWORK_DEVICE}" == *"br"* ]] && [[ "${lNETWORK_DEVICE}" == *[0-9]* ]]; then
    BR_NUM="${lNETWORK_DEVICE/br}"
    BR_NUM="${BR_NUM//[![:print:]]/}"
  fi
  if [[ "${lETH_INT}" == *"eth"* ]]; then
    ETH_NUM="${lETH_INT/eth}"
    ETH_NUM="${ETH_NUM//[![:print:]]/}"
  fi

  # used for generating startup scripts for offline analysis
  export ARCHIVE_PATH="${LOG_PATH_MODULE}"/archive-"${IMAGE_NAME}"-"${RANDOM}"

  if ! [[ -d "${ARCHIVE_PATH}" ]]; then
    mkdir "${ARCHIVE_PATH}"
  fi

  lTAP_ID=$(shuf -i 1-1000 -n 1)

  # bridge, no vlan, ip address
  export TAPDEV_0="tap${lTAP_ID}_0"
  if ifconfig | grep -q "${TAPDEV_0}"; then
    lTAP_ID=$(shuf -i 1-1000 -n 1)
    TAPDEV_0="tap${lTAP_ID}_0"
  fi
  export HOSTNETDEV_0="${TAPDEV_0}"
  print_output "[*] Creating TAP device ${ORANGE}${TAPDEV_0}${NC} ..."
  write_script_exec "echo -e \"Creating TAP device ${TAPDEV_0}\n\"" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "command -v tunctl > /dev/null || (echo \"Missing tunctl ... check your installation - install uml-utilities package\" && exit 1)" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "tunctl -t ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh 1

  if [[ "${lVLAN_ID}" != "NONE" ]]; then
    HOSTNETDEV_0="${TAPDEV_0}"."${lVLAN_ID}"
    print_output "[*] Bringing up HOSTNETDEV ${ORANGE}${HOSTNETDEV_0}${NC} / VLAN ID ${ORANGE}${lVLAN_ID}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}."
    write_script_exec "echo -e \"Bringing up HOSTNETDEV ${ORANGE}${HOSTNETDEV_0}${NC} / VLAN ID ${ORANGE}${lVLAN_ID}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}.\n\"" "${ARCHIVE_PATH}"/run.sh 0
    write_script_exec "ip link add link ${TAPDEV_0} name ${HOSTNETDEV_0} type vlan id ${lVLAN_ID}" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "ip link set ${TAPDEV_0} up" "${ARCHIVE_PATH}"/run.sh 1
  fi

  if [[ "${lIP_ADDRESS}" != "NONE" ]]; then
    # we change the host IP based on the identified IP address:
    if [[ "$(echo "${lIP_ADDRESS}" | sed 's/\./&\n/g' | grep -v -E "[0-9]+\.$")" -ne 2 ]]; then
      lHOSTIP="$(echo "${lIP_ADDRESS}" | sed 's/\./&\n/g' | sed -E 's/^[0-9]+$/2/' | tr -d '\n')"
    else
      lHOSTIP="$(echo "${lIP_ADDRESS}" | sed 's/\./&\n/g' | sed -E 's/^[0-9]+$/3/' | tr -d '\n')"
    fi
    print_output "[*] Bringing up HOSTIP ${ORANGE}${lHOSTIP}${NC} / IP address ${ORANGE}${lIP_ADDRESS}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}."
    write_script_exec "echo -e \"Bringing up HOSTIP ${ORANGE}${lHOSTIP}${NC} / IP address ${ORANGE}${lIP_ADDRESS}${NC} / TAPDEV ${ORANGE}${TAPDEV_0}${NC}.\n\"" "${ARCHIVE_PATH}"/run.sh 0

    write_script_exec "ip link set ${HOSTNETDEV_0} up" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "ip addr add ${lHOSTIP}/24 dev ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "ifconfig -a" "${ARCHIVE_PATH}"/run.sh 1
    write_script_exec "route -n" "${ARCHIVE_PATH}"/run.sh 1
  fi

  print_ln
  write_network_config_to_filesystem "${IMAGE_NAME}" "${lETH_INT}" "${lNETWORK_MODE}" "${lNETWORK_DEVICE}" "${lIP_ADDRESS}"
}

write_network_config_to_filesystem() {
  local lIMAGE_NAME="${1:-}"
  local lETH_INT="${2:-}"
  local lNETWORK_MODE="${3:-}"
  local lNETWORK_DEVICE="${4:-}"
  local lIP_ADDRESS="${5:-}"

  local lDEVICE="NA"
  local lFILE_PATH_MISSING=""
  local lFILENAME_MISSING=""
  local lDIR_NAME_MISSING=""
  local lFOUND_MISSING=""

  # mount filesystem again for network config:
  print_output "[*] Identify Qemu Image device for ${ORANGE}${LOG_PATH_MODULE}/${lIMAGE_NAME}${NC}"
  local lCNT=0
  while [[ "${lDEVICE:-NA}" == "NA" ]]; do
    lDEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${lIMAGE_NAME}")"
    lCNT=$((lCNT+1))
    if [[ "${lDEVICE:-NA}" == "NA" ]] && [[ "${lCNT}" -gt 10 ]]; then
      print_output "[-] No Qemu Image device identified - return from ${FUNCNAME[0]}"
      return
    fi
    sleep 5
  done
  sleep 1
  print_output "[*] Device mapper created at ${ORANGE}${lDEVICE}${NC}"
  print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
  mount "${lDEVICE}" "${MNT_POINT}" || true
  if mount | grep -q "${MNT_POINT}"; then
    print_output "[*] Setting network configuration in target filesystem:"
    print_output "$(indent "Network interface: ${ORANGE}${lETH_INT}${NC}")"
    print_output "$(indent "Network mode: ${ORANGE}${lNETWORK_MODE}${NC}")"
    print_output "$(indent "Bridge interface: ${ORANGE}${lNETWORK_DEVICE}${NC}")"
    print_output "$(indent "IP address: ${ORANGE}${lIP_ADDRESS}${NC}")"

    set_network_config "${lIP_ADDRESS}" "${lNETWORK_MODE}" "${lNETWORK_DEVICE}" "${lETH_INT}"

    # if there were missing files found -> we try to fix this now
    if [[ -v MISSING_FILES[@] ]]; then
      mapfile -t MISSING_FILES < <(printf "%s\n" "${MISSING_FILES[@]}" | sort -u)

      for lFILE_PATH_MISSING in "${MISSING_FILES[@]}"; do
        lFILE_PATH_MISSING="${lFILE_PATH_MISSING//[![:print:]]/}"
        print_output "[*] Checking for missing area ${ORANGE}${lFILE_PATH_MISSING}${NC} in filesystem ..."
        [[ "${lFILE_PATH_MISSING}" == *"firmadyne"* ]] && continue
        [[ "${lFILE_PATH_MISSING}" == *"/proc/"* ]] && continue
        [[ "${lFILE_PATH_MISSING}" == *"/sys/"* ]] && continue
        [[ "${lFILE_PATH_MISSING}" == *"/dev/"* ]] && continue
        [[ "${lFILE_PATH_MISSING}" == *"reboot"* ]] && continue
        # ugly false positive cleanup
        [[ "${lFILE_PATH_MISSING}" == *"EMBA_"* ]] && continue

        lFILENAME_MISSING=$(basename "${lFILE_PATH_MISSING}")
        # ensure the found path is nothing with a '*' in it:
        [[ "${lFILENAME_MISSING}" =~ \* ]] && continue
        print_output "[*] Found missing area ${ORANGE}${lFILE_PATH_MISSING}${NC} in filesystem ... trying to fix this now"
        lDIR_NAME_MISSING=$(dirname "${lFILE_PATH_MISSING}")
        if ! [[ -d "${MNT_POINT}""/${lDIR_NAME_MISSING#/}" ]]; then
          print_output "[*] Create missing directory ${ORANGE}/${lDIR_NAME_MISSING#/}${NC} in filesystem ... trying to fix this now"
          mkdir -p "${MNT_POINT}""/${lDIR_NAME_MISSING#/}" 2>/dev/null || true
        fi
        lFOUND_MISSING=$(find "${MNT_POINT}" -name "${lFILENAME_MISSING}" | head -1 || true)
        if [[ -f ${lFOUND_MISSING} ]] && ! [[ -f "${MNT_POINT}/${lDIR_NAME_MISSING#/}/${lFOUND_MISSING}" ]]; then
          print_output "[*] Recover missing file ${ORANGE}${lFILENAME_MISSING}${NC} in filesystem (${ORANGE}${MNT_POINT}/${lDIR_NAME_MISSING#/}/${lFOUND_MISSING}${NC}) ... trying to fix this now"
          cp --update=none "${lFOUND_MISSING}" "${MNT_POINT}""/${lDIR_NAME_MISSING#/}"/ || true
        fi
      done
    fi

    # as we have the filesytem mounted right before the final run we can link libnvram now
    link_libnvram_so "${MNT_POINT}" "dbg"

    # if we have a /tmp/EMBA_config_state from a previous emulation run we need to remove it
    # before the next emulation testrun
    # This file is an indiator that the initial network config was done and we can start checking
    # the network config during emulation
    rm "${MNT_POINT}"/tmp/EMBA_config_state 2>/dev/null || true

    # umount filesystem:
    umount_qemu_image "${lDEVICE}"
    delete_device_entry "${lIMAGE_NAME}" "${lDEVICE}" "${MNT_POINT}"
  fi
}

nvram_check() {
  local lIMAGE_NAME="${1:-}"
  local lMAX_THREADS_NVRAM=$((4*"$(nproc || echo 1)"))
  local lDEVICE=""
  local lWAIT_PIDS_AE=()
  local lCURRENT_DIR=""
  local lNVRAM_FILE_LIST=()
  local lNVRAM_FILE=""

  # mount filesystem again for network config:
  print_output "[*] Identify Qemu Image device for ${ORANGE}${LOG_PATH_MODULE}/${lIMAGE_NAME}${NC}"
  local lCNT=0
  while [[ "${lDEVICE:-NA}" == "NA" ]]; do
    lDEVICE="$(add_partition_emulation "${LOG_PATH_MODULE}/${lIMAGE_NAME}")"
    lCNT=$((lCNT+1))
    if [[ "${lDEVICE:-NA}" == "NA" ]] && [[ "${lCNT}" -gt 10 ]]; then
      print_output "[-] No Qemu Image device identified - return from ${FUNCNAME[0]}"
      return
    fi
    sleep 5
  done

  print_output "[*] Device mapper created at ${ORANGE}${lDEVICE}${NC}"
  print_output "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${MNT_POINT}${NC}"
  mount "${lDEVICE}" "${MNT_POINT}" || true

  if mount | grep -q "${MNT_POINT}"; then
    # we check for NVRAM access. Threshold value is a random 5
    if [[ -v NVRAMS[@] ]] && [[ "${#NVRAMS[@]}" -gt 5 ]]; then
      print_output "[*] NVRAM access detected ${ORANGE}${#NVRAMS[@]}${NC} times. Testing NVRAM access now."
      lCURRENT_DIR=$(pwd)
      cd "${MNT_POINT}" || exit
      # generate a file list of the firmware
      mapfile -t lNVRAM_FILE_LIST < <(find . -xdev -type f -not -path "*/firmadyne*" -exec file {} \; | grep "ASCII text" || true)

      if ! [[ -d "${LOG_PATH_MODULE}"/nvram ]]; then
        mkdir "${LOG_PATH_MODULE}"/nvram
      fi

      # need to check for firmadyne string in path
      for lNVRAM_FILE in "${lNVRAM_FILE_LIST[@]}"; do
        nvram_searcher_emulation "${lNVRAM_FILE/:*}" &
        lWAIT_PIDS_AE+=( "$!" )
        max_pids_protection "${lMAX_THREADS_NVRAM}" lWAIT_PIDS_AE
      done
      wait_for_pid "${lWAIT_PIDS_AE[@]}"
      cd "${lCURRENT_DIR}" || exit
    fi

    if [[ -f "${LOG_PATH_MODULE}"/nvram/nvram_files_final ]]; then
      if [[ "$(wc -l < "${LOG_PATH_MODULE}"/nvram/nvram_files_final)" -gt 0 ]]; then
        # print_output "[*] Identified the following NVRAM files:"
        # tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/nvram/nvram_files_final

        sort -u -r -h -k2 "${LOG_PATH_MODULE}"/nvram/nvram_files_final | sort -u -k1,1 | sort -r -h -k2 | head -10 > "${MNT_POINT}"/firmadyne/nvram_files || true
        # store a copy in the log dir
        cp "${MNT_POINT}"/firmadyne/nvram_files "${LOG_PATH_MODULE}"/nvram/nvram_files_final_ || true

        print_ln
        print_output "[*] Setting up ${ORANGE}nvram_files${NC} in target filesystem:"
        tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/nvram/nvram_files_final_
      fi
    fi
  fi

  # umount filesystem:
  umount_qemu_image "${lDEVICE}"
  delete_device_entry "${lIMAGE_NAME}" "${lDEVICE}" "${MNT_POINT}"
}

nvram_searcher_emulation() {
  local lNVRAM_FILE="${1:-}"

  # lets store it in tmp var for supporting binary files in the future
  local lNVRAM_FILE_TMP="${lNVRAM_FILE}"
  local lMAX_VALUES=""
  local lCOUNT=0

  if [[ "${#NVRAMS[@]}" -gt 1000 ]]; then
    lMAX_VALUES=1000
  else
    lMAX_VALUES="${#NVRAMS[@]}"
  fi

  for (( j=0; j<"${lMAX_VALUES}"; j++ )); do
    lNVRAM_ENTRY="${NVRAMS[${j}]}"
    lNVRAM_KEY=""
    # check https://github.com/pr0v3rbs/FirmAE/blob/master/scripts/inferDefault.py
    echo "${lNVRAM_ENTRY}" >> "${LOG_PATH_MODULE}"/nvram/nvram_keys.tmp
    lNVRAM_KEY=$(echo "${lNVRAM_ENTRY}" | tr -s '[:blank:]')
    lNVRAM_KEY="${lNVRAM_KEY//[![:print:]]/}"
    if [[ "${lNVRAM_KEY}" =~ [a-zA-Z0-9_] && "${#lNVRAM_KEY}" -gt 3 ]]; then
      # print_output "[*] NVRAM access detected: $ORANGE$NVRAM_KEY$NC"
      if grep -q "${lNVRAM_KEY}" "${lNVRAM_FILE_TMP}" 2>/dev/null; then
        # print_output "[*] Possible NVRAM access via key ${ORANGE}${lNVRAM_KEY}${NC} found in NVRAM file ${ORANGE}${lNVRAM_FILE}${NC}."
        lCOUNT=$((lCOUNT + 1))
      fi
      echo "${lNVRAM_KEY}" >> "${LOG_PATH_MODULE}"/nvram/nvram_keys.log
    fi
  done

  if [[ "${lCOUNT}" -gt 5 ]]; then
    print_output "[*] ${lNVRAM_FILE/\.} ${lCOUNT} ASCII_text"
    echo "${lNVRAM_FILE/\.} ${lCOUNT} ASCII_text" >> "${LOG_PATH_MODULE}"/nvram/nvram_files_final
  fi
}

run_emulated_system() {
  local lIP_ADDRESS="${1:-}"
  local lIMAGE_NAME="${2:-}"
  local lINIT_FILE="${3:-}"
  local lARCH_END="${4:-}"

  sub_module_title "Final system emulation for ${lIP_ADDRESS} - ${lINIT_FILE} - ${KINIT} - ${lARCH_END} - ${lIMAGE_NAME}"

  local IMAGE="${LOG_PATH_MODULE}/${lIMAGE_NAME}"

  export KERNEL_V=".4"
  get_kernel_version
  if [[ -n "${KERNEL_V:-}" ]]; then
    print_output "[*] Kernel ${KERNEL_V}.x detected -> Using Kernel v4.x"
    # KERNEL_V=".$KERNEL_V"
    KERNEL_V=".4"
  fi

  local lNET_NUM=0
  local lNET_ID=0
  local lCPU=""
  local lKERNEL=""
  local lQEMU_BIN=""
  local lQEMU_MACHINE=""
  local lQEMU_DISK=""
  local lQEMU_PARAMS=""
  local lQEMU_NETWORK=""
  local lQEMU_ROOTFS=""
  local lCONSOLE="ttyS0"
  local lQEMU_NET_DEVICE=""

  if [[ "${lARCH_END}" == "mipsel" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-${lARCH_END}"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64r2el" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-${lARCH_END}"
    lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mipseb" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-mips"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64r2eb" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-mips64"
    lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64v1eb" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-mips64"
    # lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64v1el" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-mips64el"
    # lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "mips64n32eb" ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}${KERNEL_V}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-mips64"
    lCPU="-cpu MIPS64R2-generic"
    lQEMU_MACHINE="malta"
  elif [[ "${lARCH_END}" == "armel"* ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/zImage.${lARCH_END}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/zImage.${lARCH_END}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-arm"
    lQEMU_MACHINE="virt"
  elif [[ "${lARCH_END}" == "arm64el"* ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/Image.${lARCH_END}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/Image.${lARCH_END}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-aarch64"
    # lCONSOLE="ttyAMA0"
    lCPU="-cpu cortex-a57"
    lQEMU_MACHINE="virt"
  elif [[ "${lARCH_END}" == "x86el"* ]]; then
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/bzImage.${lARCH_END}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/bzImage.${lARCH_END}"
    else
      print_output "[-] Missing kernel for ${L10_KERNEL_V_LONG} / ${lARCH_END}"
      return
    fi
    lQEMU_BIN="qemu-system-x86_64"
    lQEMU_MACHINE="pc-i440fx-8.2"
  elif [[ "${lARCH_END}" == "nios2el" ]]; then
    # not implemented -> Future
    if [[ -f "${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}" ]]; then
      lKERNEL="${BINARY_DIR}/Linux-Kernel-v${L10_KERNEL_V_LONG}/vmlinux.${lARCH_END}"
    else
      lKERNEL="${BINARY_DIR}/vmlinux.${lARCH_END}"
    fi
    lQEMU_BIN="qemu-system-nios2"
    lQEMU_MACHINE="10m50-ghrd"
  else
    lQEMU_BIN="NA"
  fi

  if [[ "${ARCH}" == "ARM"* ]]; then
    lQEMU_DISK="-drive if=none,file=${IMAGE},format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    lQEMU_PARAMS="-audiodev driver=none,id=none"
    lQEMU_ROOTFS="/dev/vda1"
    # newer kernels use virtio only
    lQEMU_NET_DEVICE="virtio-net-device"
  elif [[ "${ARCH}" == "NIOS2" ]]; then
    lQEMU_PARAMS="-monitor none"
    lQEMU_DISK="-drive file=${IMAGE},format=raw"
    lQEMU_NET_DEVICE="virtio-net-device"
  elif [[ "${ARCH}" == "MIPS" ]] || [[ "${lARCH_END}" == "x86el" ]] || [[ "${lARCH_END}" == "mips64"* ]]; then
    lQEMU_DISK="-drive if=ide,format=raw,file=${IMAGE}"
    lQEMU_PARAMS=""
    lQEMU_ROOTFS="/dev/sda1"
    lQEMU_NET_DEVICE="e1000"
  fi

  if [[ "${ARCH}" == "MIPS" ]] || [[ "${lARCH_END}" == "x86el" ]] || [[ "${lARCH_END}" == "mips64"* ]] || [[ "${ARCH}" == "ARM"* ]]; then
    if [[ -n "${ETH_NUM}" ]]; then
      # if we found an eth interface we use this
      lNET_NUM="${ETH_NUM}"
    elif [[ -n "${BR_NUM}" ]]; then
      # if we found no eth interface but a br interface we use this
      lNET_NUM="${BR_NUM}"
    else
      # fallback - we connect id 0
      lNET_NUM=0
    fi

    # 6 Interfaces -> 0-5
    for lNET_ID in {0..5}; do
      if [[ "${lNET_ID}" == "${lNET_NUM}" ]];then
        # if MATCH in IPS_INT -> connect this interface to host
        print_output "[*] Connect interface: ${ORANGE}${lNET_ID}${NC} to host"
        lQEMU_NETWORK+=" -device ${lQEMU_NET_DEVICE},netdev=net${lNET_ID}"
        lQEMU_NETWORK+=" -netdev tap,id=net${lNET_ID},ifname=${TAPDEV_0},script=no"
      else
        # only 0-3 are handled via placeholder interfaces
        if [[ "${lNET_ID}" -gt 3 ]]; then
          continue
        fi
        # on ARM we have currently only one interface and we need to connect this to the host
        # This means we do not place placeholder interfaces for ARM architecture
        if [[ "${ARCH}" != "ARM"* ]]; then
          print_output "[*] Create socket placeholder interface: ${ORANGE}${lNET_ID}${NC}"
          # place a socket connection placeholder:
          lQEMU_NETWORK+=" -device ${lQEMU_NET_DEVICE},netdev=net${lNET_ID}"
          lQEMU_NETWORK+=" -netdev socket,id=net${lNET_ID},listen=:200${lNET_ID}"
        fi
      fi
    done
  fi

  if [[ -z "${lQEMU_NETWORK}" ]]; then
    print_output "[!] No network interface config created ... stop further emulation"
    print_output "[-] No firmware emulation ${ORANGE}${ARCH}${NC} / ${ORANGE}${lIMAGE_NAME}${NC} possible"
    return
  fi

  # dirty workaround to fill the KERNEL which is used later on
  export KERNEL="${lKERNEL}"

  if [[ "${lQEMU_BIN}" != "NA" ]]; then
    run_qemu_final_emulation "${lCONSOLE}" "${lCPU}" "${lKERNEL}" "${lQEMU_BIN}" "${lQEMU_MACHINE}" "${lQEMU_DISK}" "${lQEMU_PARAMS}" "${lQEMU_NETWORK}" "${lQEMU_ROOTFS}" "${lIP_ADDRESS}" "${lIMAGE_NAME}" "${lINIT_FILE}" "${lARCH_END}" &
  else
    print_output "[-] No firmware emulation ${ORANGE}${ARCH}${NC} / ${ORANGE}${lIMAGE_NAME}${NC} possible"
  fi
}

run_qemu_final_emulation() {
  local lCONSOLE="${1:-}"
  local lCPU="${2:-}"
  local lKERNEL="${3:-}"
  local lQEMU_BIN="${4:-}"
  local lQEMU_MACHINE="${5:-}"
  local lQEMU_DISK="${6:-}"
  local lQEMU_PARAMS="${7:-}"
  local lQEMU_NETWORK="${8:-}"
  local lQEMU_ROOTFS="${9:-}"
  local lIP_ADDRESS="${10:-}"
  local lIMAGE_NAME="${11:-}"
  local lINIT_FILE="${12:-}"
  local lARCH_END="${13:-}"

  check_qemu_instance_l10

  print_output "[*] Qemu parameters used in run mode:"
  print_output "$(indent "MACHINE: ${ORANGE}${lQEMU_MACHINE}${NC}")"
  print_output "$(indent "KERNEL: ${ORANGE}${lKERNEL}${NC}")"
  print_output "$(indent "DISK: ${ORANGE}${lQEMU_DISK}${NC}")"
  print_output "$(indent "KINIT: ${ORANGE}${KINIT}${NC}")"
  print_output "$(indent "ROOT_DEV: ${ORANGE}${lQEMU_ROOTFS}${NC}")"
  print_output "$(indent "QEMU: ${ORANGE}${lQEMU_BIN}${NC}")"
  print_output "$(indent "NETWORK: ${ORANGE}${lQEMU_NETWORK}${NC}")"
  print_output "$(indent "Init file: ${ORANGE}${lINIT_FILE}${NC}")"
  print_output "$(indent "Console interface: ${ORANGE}${lCONSOLE}${NC}")"
  print_ln
  print_output "[*] Starting firmware emulation ${ORANGE}${lQEMU_BIN} / ${lARCH_END} / ${lIMAGE_NAME} / ${lIP_ADDRESS}${NC} ... use Ctrl-a + x to exit"
  print_ln

  write_script_exec "echo -e \"[*] Starting firmware emulation ${ORANGE}${lQEMU_BIN} / ${lARCH_END} / ${lIMAGE_NAME} / ${lIP_ADDRESS}${NC} ... use Ctrl-a + x to exit\n\"" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "echo -e \"[*] For emulation state please monitor the ${ORANGE}qemu.serial.log${NC} file\n\"" "${ARCHIVE_PATH}"/run.sh 0
  write_script_exec "echo -e \"[*] For shell access check localhost port ${ORANGE}4321${NC} via telnet\n\"" "${ARCHIVE_PATH}"/run.sh 0

  write_script_exec "timeout --preserve-status --signal SIGINT 6000 ${lQEMU_BIN} -m 2048 -M ${lQEMU_MACHINE} ${lCPU} -kernel ${lKERNEL} ${lQEMU_DISK} -append \"root=${lQEMU_ROOTFS} console=${lCONSOLE} nandsim.parts=64,64,64,64,64,64,64,64,64,64 ${KINIT} rw debug ignore_loglevel print-fatal-signals=1 EMBA_NET=${EMBA_NET} EMBA_NVRAM=${EMBA_NVRAM} EMBA_KERNEL=${EMBA_KERNEL} EMBA_ETC=${EMBA_ETC} user_debug=0 firmadyne.syscall=1\" -nographic ${lQEMU_NETWORK} ${lQEMU_PARAMS} -serial file:${LOG_PATH_MODULE}/qemu.final.serial.log -serial telnet:localhost:4321,server,nowait -serial unix:/tmp/qemu.${lIMAGE_NAME}.S1,server,nowait -monitor unix:/tmp/qemu.${lIMAGE_NAME},server,nowait ; pkill -9 -f tail.*-F.*\"${LOG_PATH_MODULE}\"" "${ARCHIVE_PATH}"/run.sh 1
}

check_online_stat() {
  local lIPS_INT_VLAN_CFG="${1:-}"
  local lIMAGE_NAME="${3:-}"

  local lIP_ADDRESS=""
  lIP_ADDRESS=$(echo "${lIPS_INT_VLAN_CFG}" | cut -d\; -f2)

  local lNMAP_LOG="nmap_emba_${lIPS_INT_VLAN_CFG//\;/-}.txt"

  local lPING_CNT=0
  local lSYS_ONLINE=0
  local lTCP_SERV_NETSTAT_ARR=()
  local lUDP_SERV_NETSTAT_ARR=()
  local lNMAP_SERV_UDP_ARR=()
  local lNMAP_SERV_TCP_ARR=()

  # wait 20 secs after boot before starting pinging
  sleep 20

  local lMAX_PING_CNT=120
  # we write the results to a tmp file. This is needed to only have the results of the current emulation round
  # for further processing available
  # we try pinging the system for 30 times with 5 secs sleeptime in between
  # if the system is reachable we go ahead
  while [[ "${lPING_CNT}" -lt "${lMAX_PING_CNT}" && "${lSYS_ONLINE}" -eq 0 ]]; do
    # lets use the default ping command first
    if ping -c 1 "${lIP_ADDRESS}" &> /dev/null; then
      print_output "[+] Host with ${ORANGE}${lIP_ADDRESS}${GREEN} is reachable via ICMP."
      ping -c 1 "${lIP_ADDRESS}" | tee -a "${LOG_FILE}" || true
      print_ln
      write_log "${GREEN}[+] Host with ${ORANGE}${lIP_ADDRESS}${GREEN} is reachable via ICMP." "${TMP_DIR}"/online_stats.tmp
      lSYS_ONLINE=1
    fi

    # and as second check we can use hping
    if [[ "$(hping3 -n -c 1 "${lIP_ADDRESS}" 2>/dev/null | grep -c "^len=")" -gt 0 ]]; then
      print_output "[+] Host with ${ORANGE}${lIP_ADDRESS}${GREEN} is reachable on TCP port 0 via hping."
      hping3 -n -c 1 "${lIP_ADDRESS}" | tee -a "${LOG_FILE}" || true
      print_ln
      if [[ "${lSYS_ONLINE}" -ne 1 ]]; then
        if ping -c 1 "${lIP_ADDRESS}" &> /dev/null; then
          print_output "[+] Host with ${ORANGE}${lIP_ADDRESS}${GREEN} is reachable via ICMP."
          ping -c 1 "${lIP_ADDRESS}" | tee -a "${LOG_FILE}" || true
          print_ln
          write_log "${GREEN}[+] Host with ${ORANGE}${lIP_ADDRESS}${GREEN} is reachable via ICMP." "${TMP_DIR}"/online_stats.tmp
        fi
      fi
      print_ln
      write_log "${GREEN}[+] Host with ${ORANGE}${lIP_ADDRESS}${GREEN} is reachable on TCP port 0 via hping." "${TMP_DIR}"/online_stats.tmp
      lSYS_ONLINE=1
    fi

    lPING_CNT=$((lPING_CNT+1))
    if [[ "${lSYS_ONLINE}" -eq 0 ]]; then
      print_output "[*] Host with ${ORANGE}${lIP_ADDRESS}${NC} is not reachable for ${lPING_CNT} time(s) - max cnt ${lMAX_PING_CNT}." "no_log"
      lSYS_ONLINE=0
      sleep 5
    fi
  done

  # looks as we can ping the system. Now, we wait some time before doing our Nmap portscan
  if [[ "${lSYS_ONLINE}" -ne 1 ]]; then
    print_output "[*] Host with ${ORANGE}${lIP_ADDRESS}${NC} is not reachable."
  else
    print_output "[*] Give the system another 60 seconds to ensure the boot process is finished.\n" "no_log"
    sleep 60
    print_output "[*] Default Nmap portscan for ${ORANGE}${lIP_ADDRESS}${NC}"
    # write_link "${ARCHIVE_PATH}"/"${lNMAP_LOG}"
    print_ln

    # this is just for the logfile
    if ! ping -c 1 "${lIP_ADDRESS}" | tee -a "${LOG_FILE}"; then
      print_output "[-] Warning: System was already available but it does not respond to ping anymore."
      print_output "[-] Probably the IP address of the system has changed."
    fi
    print_ln
    local lCNT=1
    local lMAX_NMAP_RETRIES=10
    nmap -Pn -n -A -sSV --host-timeout 10m -oA "${ARCHIVE_PATH}/${lCNT}_$(basename "${lNMAP_LOG}")" "${lIP_ADDRESS}" | tee -a "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}" || true
    tee -a "${LOG_FILE}" < "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}"

    lMAX_NMAP_RETRIES=10
    while [[ "$(grep -c "udp.*open\ \|/tcp.*open\ " "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}")" -lt "${MIN_TCP_SERV}" ]]; do
      if [[ "$(grep -c "udp.*open\ \|/tcp.*open\ " "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}")" -gt 0 ]]; then
        print_ln
        print_output "[+] Already dedected running network services via Nmap ... further detection active - CNT: ${lCNT}"
        write_link "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}"
        print_ln
      fi
      lCNT=$((lCNT+1))
      print_output "[*] Give the system another 60 seconds to ensure the boot process is finished - ${lCNT}/${lMAX_NMAP_RETRIES}.\n" "no_log"
      sleep 60
      # we store our Nmap logs in dedicated files (${lCNT}_nmap_log_file):
      nmap -Pn -n -A -sSV --host-timeout 10m -oA "${ARCHIVE_PATH}/${lCNT}_$(basename "${lNMAP_LOG}")" "${lIP_ADDRESS}" | tee -a "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}" || true
      # ensure we have the last results also in our main Nmap log file:
      # cp "${ARCHIVE_PATH}"/"${lCNT}_${lNMAP_LOG}" "${ARCHIVE_PATH}"/"${lNMAP_LOG}"
      tee -a "${LOG_FILE}" < "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}"
      [[ "${lCNT}" -ge "${lMAX_NMAP_RETRIES}" ]] && break
    done
    # get a backup of our current results and add the later nmap scans to this file for the web report
    cp "${ARCHIVE_PATH}/${lCNT}_${lNMAP_LOG}" "${ARCHIVE_PATH}/${lNMAP_LOG}"

    mapfile -t lTCP_SERV_NETSTAT_ARR < <(grep -a "^tcp.*LISTEN" "${LOG_PATH_MODULE}"/qemu*.log | grep -v "127.0.0.1" | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u || true)
    mapfile -t lUDP_SERV_NETSTAT_ARR < <(grep -a "^udp.*" "${LOG_PATH_MODULE}"/qemu*.log | grep -v "127.0.0.1" | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u || true)
    # check the already created nmap log for open services to include these services in the final scan
    mapfile -t lNMAP_SERV_TCP_ARR < <(grep -o -E "[0-9]+/open/tcp" "${ARCHIVE_PATH}/${lNMAP_LOG}" | cut -d '/' -f1 | sort -u || true)
    mapfile -t lNMAP_SERV_UDP_ARR < <(grep -o -E "[0-9]+/open/udp" "${ARCHIVE_PATH}/${lNMAP_LOG}" | cut -d '/' -f1 | sort -u || true)

    if [[ "${#SERVICES_STARTUP[@]}" -gt 0 ]] || [[ "${#lTCP_SERV_NETSTAT_ARR[@]}" -gt 0 ]] || \
      [[ "${#lUDP_SERV_NETSTAT_ARR[@]}" -gt 0 ]] || [[ "${#lNMAP_SERV_TCP_ARR[@]}" -gt 0 ]] || \
      [[ "${#lNMAP_SERV_UDP_ARR[@]}" -gt 0 ]]; then
      local lUDP_SERV_NETSTAT=""
      local lUDP_SERV_STARTUP=""
      local lUDP_SERV=""
      local lTCP_SERV_NETSTAT=""
      local lTCP_SERV_STARTUP=""
      local lTCP_SERV=""
      local lTCP_SERV_ARR=()
      local lUDP_SERV_ARR=()
      local lPORTS_TO_SCAN=""

      # write all services into a one liner for output:
      print_ln
      shopt -s extglob
      # rewrite our array into a nice string for printing it
      if [[ "${#TCP_SERVICES_STARTUP[@]}" -gt 0 ]]; then
        printf -v lTCP_SERV "%s " "${TCP_SERVICES_STARTUP[@]}"
        # # replace \n and ' ' with ,
        lTCP_SERV_STARTUP=${lTCP_SERV//+([$'\n'\ ])/,}
        [[ "${lTCP_SERV_STARTUP}" != "," ]] && print_output "[*] TCP Services detected via startup: ${ORANGE}${lTCP_SERV_STARTUP}${NC}"
      fi
      # rewrite our array into a nice string for printing it
      if [[ "${#UDP_SERVICES_STARTUP[@]}" -gt 0 ]]; then
        printf -v lUDP_SERV "%s " "${UDP_SERVICES_STARTUP[@]}"
        lUDP_SERV_STARTUP=${lUDP_SERV//+([$'\n'\ ])/,}
        [[ "${lUDP_SERV_STARTUP}" != "," ]] && print_output "[*] UDP Services detected via startup: ${ORANGE}${lUDP_SERV_STARTUP}${NC}"
      fi

      # rewrite our array into a nice string for printing it
      if [[ "${#lTCP_SERV_NETSTAT_ARR[@]}" -gt 0 ]]; then
        printf -v lTCP_SERV "%s " "${lTCP_SERV_NETSTAT_ARR[@]}"
        lTCP_SERV_NETSTAT=${lTCP_SERV//+([$'\n'\ ])/,}
        [[ "${lTCP_SERV_NETSTAT}" != "," ]] && print_output "[*] TCP Services detected via netstat: ${ORANGE}${lTCP_SERV_NETSTAT}${NC}"
      fi
      # rewrite our array into a nice string for printing it
      if [[ "${#lUDP_SERV_NETSTAT_ARR[@]}" -gt 0 ]]; then
        printf -v lUDP_SERV "%s " "${lUDP_SERV_NETSTAT_ARR[@]}"
        lUDP_SERV_NETSTAT=${lUDP_SERV//+([$'\n'\ ])/,}
        [[ "${lUDP_SERV_NETSTAT}" != "," ]] && print_output "[*] UDP Services detected via netstat: ${ORANGE}${lUDP_SERV_NETSTAT}${NC}"
      fi
      if [[ "${#lNMAP_SERV_TCP_ARR[@]}" -gt 0 ]]; then
        printf -v lTCP_SERV "%s " "${lNMAP_SERV_TCP_ARR[@]}"
        lTCP_SERV_NMAP=${lTCP_SERV//+([$'\n'\ ])/,}
        [[ "${lTCP_SERV_NMAP}" != "," ]] && print_output "[*] TCP Services detected via Nmap: ${ORANGE}${lTCP_SERV_NMAP}${NC}"
      fi
      if [[ "${#lNMAP_SERV_UDP_ARR[@]}" -gt 0 ]]; then
        printf -v lUDP_SERV "%s " "${lNMAP_SERV_UDP_ARR[@]}"
        lUDP_SERV_NMAP=${lUDP_SERV//+([$'\n'\ ])/,}
        [[ "${lUDP_SERV_NMAP}" != "," ]] && print_output "[*] UDP Services detected via Nmap: ${ORANGE}${lUDP_SERV_NMAP}${NC}"
      fi

      print_ln

      # work with this:
      lUDP_SERV_ARR=( "${UDP_SERVICES_STARTUP[@]}" "${lUDP_SERV_NETSTAT_ARR[@]}" "${#lNMAP_SERV_UDP_ARR[@]}")
      lTCP_SERV_ARR=( "${TCP_SERVICES_STARTUP[@]}" "${lTCP_SERV_NETSTAT_ARR[@]}" "${#lNMAP_SERV_TCP_ARR[@]}")
      # we add some default services that we always check in our final Nmap scan
      lTCP_SERV_ARR+=(21)
      lTCP_SERV_ARR+=(22)
      lTCP_SERV_ARR+=(80)
      lTCP_SERV_ARR+=(443)
      lTCP_SERV_ARR+=(8080)

      mapfile -t lTCP_SERV_ARR < <(printf "%s\n" "${lTCP_SERV_ARR[@]}" | sort -u)
      mapfile -t lUDP_SERV_ARR < <(printf "%s\n" "${lUDP_SERV_ARR[@]}" | sort -u)
      if [[ "${#lTCP_SERV_ARR[@]}" -gt 0 ]]; then
        printf -v lTCP_SERV "%s " "${lTCP_SERV_ARR[@]}"
        lTCP_SERV="${lTCP_SERV//+([$'\n'\ ])/,}"
        # print_output "[*] TCP Services detected: ${ORANGE}${lTCP_SERV}${NC}"
      fi
      if [[ "${#lUDP_SERV_ARR[@]}" -gt 0 ]]; then
        printf -v lUDP_SERV "%s " "${lUDP_SERV_ARR[@]}"
        lUDP_SERV="${lUDP_SERV//+([$'\n'\ ])/,}"
        # print_output "[*] UDP Services detected: ${ORANGE}${lUDP_SERV}${NC}"
      fi

      lUDP_SERV="U:${lUDP_SERV#,}"
      lTCP_SERV="T:${lTCP_SERV#,}"
      # remove the last ',' ... 123,234,345, -> 123,234,345
      lTCP_SERV="${lTCP_SERV%,}"
      lUDP_SERV="${lUDP_SERV%,}"
      shopt -u extglob

      if [[ "${lTCP_SERV}" =~ ^T:[0-9].* ]]; then
        print_output "[*] Checking TCP services ${ORANGE}${lTCP_SERV}${NC}"
        lPORTS_TO_SCAN="${lTCP_SERV}"
      fi
      if [[ "${lUDP_SERV}" =~ ^U:[0-9].* ]]; then
        print_output "[*] Checking UDP services ${ORANGE}${lUDP_SERV}${NC}"
        if [[ "${lPORTS_TO_SCAN}" =~ ^T:[0-9].* ]]; then
          lPORTS_TO_SCAN+=",${lUDP_SERV}"
        else
          lPORTS_TO_SCAN="${lUDP_SERV}"
        fi
      fi

      if [[ "${lTCP_SERV}" =~ ^T:[0-9].* ]] || [[ "${lUDP_SERV}" =~ ^U:[0-9].* ]]; then
        print_ln
        print_output "[*] Nmap portscan for network services (${ORANGE}${lPORTS_TO_SCAN}${NC}) started during system init on ${ORANGE}${lIP_ADDRESS}${NC}"
        # link is for the next Nmap results:
        write_link "${ARCHIVE_PATH}/${lNMAP_LOG}"
        print_ln
        nmap -Pn -n -sSUV --host-timeout 30m -p "${lPORTS_TO_SCAN}" -oA "${ARCHIVE_PATH}/nmap_emba_${lIPS_INT_VLAN_CFG//\;/-}"_dedicated "${lIP_ADDRESS}" | tee -a "${ARCHIVE_PATH}/${lNMAP_LOG}" "${LOG_FILE}" || true
      fi
    fi
  fi

  print_output "[*] Call to stop emulation process - Source ${FUNCNAME[0]}" "no_log"
  stopping_emulation_process "${lIMAGE_NAME}"
  cleanup_emulator "${lIMAGE_NAME}"

  color_qemu_log "${LOG_PATH_MODULE}/qemu.final.serial.log"

  pkill -9 -f "tail -F ${LOG_PATH_MODULE}/qemu.final.serial.log" || true &>/dev/null
}

stopping_emulation_process() {
  local lIMAGE_NAME="${1:-}"

  print_output "[*] Stopping emulation process" "no_log"
  pkill -9 -f "qemu-system-.*${lIMAGE_NAME}.*" &>/dev/null || true
  sleep 1
}

create_emulation_archive() {
  sub_module_title "Archive to re-run emulated environment"
  print_output "With the following archive it is possible to rebuild the created emulation environment fully automated."

  local lKERNEL="${1:-}"
  local lIMAGE="${2:-}"
  local lARCHIVE_PATH="${3:-}"
  local lIPS_INT_VLAN_CFG_mod="${4:-}"
  local lARCH_NAME=""
  local lDEVICE="NA"

  if [[ "${FINAL_FW_RM}" -ne 1 ]]; then
    # we only copy the kernel and the firmware image to the archive if FINAL_FW_RM is not set
    cp "${lKERNEL}" "${lARCHIVE_PATH}" || print_error "[-] Error in kernel copy procedure"

    # we need to ensure that the EMBA_config_state file gets removed
    local lCNT=0
    while [[ "${lDEVICE:-NA}" == "NA" ]]; do
      lDEVICE="$(add_partition_emulation "${lIMAGE}")"
      lCNT=$((lCNT+1))
      if [[ "${lDEVICE:-NA}" == "NA" ]] && [[ "${lCNT}" -gt 10 ]]; then
        print_output "[-] No Qemu Image device identified - return now from ${FUNCNAME[0]}"
        return
      fi
      sleep 5
    done

    mount "${lDEVICE}" "${MNT_POINT}" || true
    rm "${MNT_POINT}"/tmp/EMBA_config_state 2>/dev/null || true
    umount_qemu_image "${lDEVICE}"
    delete_device_entry "$(basename "${lIMAGE}")" "${lDEVICE}" "${MNT_POINT}"

    cp "${lIMAGE}" "${lARCHIVE_PATH}" || print_error "[-] Error in image copy procedure"
  fi

  if [[ -f "${LOG_PATH_MODULE}"/"${NMAP_LOG}" ]]; then
    mv "${LOG_PATH_MODULE}"/"${NMAP_LOG}" "${lARCHIVE_PATH}" || print_error "[-] Error in Nmap results copy procedure"
    mv "${LOG_PATH_MODULE}"/nmap_emba_"${lIPS_INT_VLAN_CFG_mod}"* "${lARCHIVE_PATH}" || print_error "[-] Error in Nmap results copy procedure"
  fi

  echo "${lIPS_INT_VLAN_CFG_mod}" >> "${lARCHIVE_PATH}"/emulation_config.txt || true
  cat "${L10_SYS_EMU_RESULTS}" >> "${lARCHIVE_PATH}"/emulation_config.txt || true

  if [[ -v ARCHIVE_PATH ]] && [[ -f "${lARCHIVE_PATH}"/run.sh ]]; then
    chmod +x "${lARCHIVE_PATH}"/run.sh
    sed -i 's/-serial\ file:.*\/l10_system_emulation\/qemu\.final\.serial\.log/-serial\ file:\.\/qemu\.serial\.log/g' "${lARCHIVE_PATH}"/run.sh
    # fix the path for the kernel which is currently something like ./Linux-Kernel/vmlinux.mipsel.4
    # and should be ./vmlinux.mipsel.4
    local lL10_KERNEL_V_LONG_TMP="${L10_KERNEL_V_LONG}"
    if [[ "${lARCH_END}" == *"x86el"* ]] && [[ "${L10_KERNEL_V_LONG}" == "4.1.52" ]]; then
      # for x86el we currently have kernel issues
      lL10_KERNEL_V_LONG_TMP="4.1.17"
    fi
    sed -i "s/\.\/Linux-Kernel-v${lL10_KERNEL_V_LONG_TMP}\//\.\//g" "${lARCHIVE_PATH}"/run.sh

    if [[ "${FINAL_FW_RM}" -ne 1 ]]; then
      # create archive
      lARCH_NAME="$(basename "${lARCHIVE_PATH}")".tar.gz
      tar -czvf "${LOG_PATH_MODULE}"/"${lARCH_NAME}" "${lARCHIVE_PATH}"
      if [[ -f "${LOG_PATH_MODULE}"/"${lARCH_NAME}" ]]; then
        print_ln
        print_output "[*] Qemu emulation archive created in log directory: ${ORANGE}${lARCH_NAME}${NC}" "" "${LOG_PATH_MODULE}/${lARCH_NAME}"
        print_ln
      fi
    else
      print_output "[*] NO Qemu emulation archive created - FINAL_FW_RM was set or \'-r\' parameter was used."
    fi
  else
    print_output "[-] No run script created ..."
  fi
}

# EXECUTE: 0 -> just write script
# EXECUTE: 1 -> execute and write script
# EXECUTE: 2 -> just execute
reset_network_emulation() {
  local lIMAGE_NAME="${1:-0}"
  local lEXECUTE="${2:-0}"

  local lEXECUTE_tmp=0

  if ! [[ -v lIMAGE_NAME ]] || ! [[ -v ARCHIVE_PATH ]]; then
    return
  fi

  # Todo: handle network shutdown also on restarted tests
  if [[ "${RESTART}" -ne 0 ]]; then
    return
  fi

  if [[ "${lEXECUTE}" -ne 0 ]]; then
    print_output "[*] Stopping Qemu emulation ..." "no_log"
    pkill -9 -f "qemu-system-.*${lIMAGE_NAME}.*" || true &>/dev/null
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && ! grep -q "Deleting route" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    write_script_exec "echo -e \"Deleting route ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi
  if [[ -v HOSTNETDEV_0 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip route flush dev" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "[*] Deleting route..." "no_log"
    write_script_exec "ip route flush dev ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE}"
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "Bringing down TAP device" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "[*] Bringing down TAP device..." "no_log"
    write_script_exec "echo -e \"Bringing down TAP device ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi
  if [[ "${lEXECUTE}" -lt 2 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    lEXECUTE_tmp=1
  else
    lEXECUTE_tmp="${lEXECUTE}"
  fi
  if [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    write_script_exec "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE_tmp}"
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "Removing VLAN" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "Removing VLAN..." "no_log"
    write_script_exec "echo -e \"Removing VLAN ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi

  if [[ "${lEXECUTE}" -lt 2 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    lEXECUTE_tmp=1
  else
    lEXECUTE_tmp="${lEXECUTE}"
  fi
  if [[ -v HOSTNETDEV_0 ]]; then
    if [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
      write_script_exec "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE_tmp}"
    fi
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "Deleting TAP device" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "Deleting TAP device ${TAPDEV_0}..." "no_log"
    write_script_exec "echo -e \"Deleting TAP device ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi

  if [[ "${lEXECUTE}" -lt 2 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    lEXECUTE_tmp=1
  else
    lEXECUTE_tmp="${lEXECUTE}"
  fi
  if [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    write_script_exec "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE_tmp}"
  fi
}

write_script_exec() {
  local lCOMMAND="${1:-}"
  # SCRIPT_WRITE: File to write
  local lSCRIPT_WRITE="${2:-}"

  # EXECUTE: 0 -> just write script
  # EXECUTE: 1 -> execute and write script
  # EXECUTE: 2 -> just execute
  local lEXECUTE="${3:-0}"
  local lPID=""

  if [[ "${lEXECUTE}" -ne 0 ]];then
    eval "${lCOMMAND}" || true &
    lPID="$!"
    disown "${lPID}" 2> /dev/null || true
  fi

  if [[ "${lEXECUTE}" -ne 2 ]];then
    if ! [[ -f "${lSCRIPT_WRITE}" ]]; then
      # just in case we have our script not already there we set it up now
      echo "#!/bin/bash -p" > "${lSCRIPT_WRITE}"
    fi

    # for the final script we need to adjust the paths:
    if [[ "${lCOMMAND}" == *"qemu-system-"* ]]; then
      # fix path for kernel: /external/EMBA_Live_bins/vmlinux.mipsel.4 -> ./vmlinux.mipsel.4
      # shellcheck disable=SC2001
      lCOMMAND=$(echo "${lCOMMAND}" | sed 's#-kernel\ .*\/EMBA_Live_bins\/#-kernel\ .\/#g')
      # shellcheck disable=SC2001
      lCOMMAND=$(echo "${lCOMMAND}" | sed "s#${IMAGE:-}#\.\/${IMAGE_NAME:-}#g")
      # shellcheck disable=SC2001
      lCOMMAND=$(echo "${lCOMMAND}" | sed "s|\"${LOG_PATH_MODULE:-}\"|\.|g")
      # remove the timeout from the qemu startup command
      lCOMMAND="${lCOMMAND#timeout --preserve-status --signal SIGINT [[:digit:]]* }"
      # remove the tail kill command
      lCOMMAND="${lCOMMAND% ; pkill -9 -f tail.*-F.*.}"
    fi

    echo "${lCOMMAND}" >> "${lSCRIPT_WRITE}"
  fi
}

get_binary() {
  local lBINARY_NAME="${1:-}"
  local lARCH_END="${2:-}"
  local lMUSL_VER="${3:-}"

  # '${lBINARY_NAME/\.*}' -> strip the .so from libnvram.so and libnvram_ioctl.so
  if [[ "${lBINARY_NAME}" == *"busybox"* ]] && [[ -f "${BINARY_DIR}/${lBINARY_NAME}-v${L10_BB_VER}/${lBINARY_NAME}.${lARCH_END}" ]]; then
    echo "${BINARY_DIR}/${lBINARY_NAME}-v${L10_BB_VER}/${lBINARY_NAME}.${lARCH_END}"
  elif [[ -f "${BINARY_DIR}/${lBINARY_NAME/_dbg*}/${lBINARY_NAME}.${lARCH_END}_musl_${lMUSL_VER}" ]]; then
    # use sub-directories for the different binaries:
    # will be used in the future
    echo "${BINARY_DIR}/${lBINARY_NAME/_dbg*}/${lBINARY_NAME}.${lARCH_END}_musl_${lMUSL_VER}"
  elif [[ -f "${BINARY_DIR}/${lBINARY_NAME/_nondbg*}/${lBINARY_NAME}.${lARCH_END}_musl_${lMUSL_VER}" ]]; then
    # use sub-directories for the different binaries:
    # will be used in the future
    echo "${BINARY_DIR}/${lBINARY_NAME/_nondbg*}/${lBINARY_NAME}.${lARCH_END}_musl_${lMUSL_VER}"
  elif [[ -f "${BINARY_DIR}/${lBINARY_NAME}/${lBINARY_NAME}.${lARCH_END}" ]]; then
    echo "${BINARY_DIR}/${lBINARY_NAME}/${lBINARY_NAME}.${lARCH_END}"
  else
    echo "NA"
  fi
}

add_partition_emulation() {
  local lIMAGE_PATH=""
  local lDEV_PATH="NA"
  local lFOUND=false
  local lCNT=0
  local lDEV_NR=0

  while (losetup | grep -q "${1}"); do
    local lLOOP=""
    ((lCNT+=1))
    lLOOP=$(losetup -a | grep "${1}" | sort -u)
    # we try to get rid of the entry nicely
    losetup -d "${lLOOP/:*}"
    if losetup -a | grep -q "${1}"; then
      # and now we go the brutal way
      losetup -D
      dmsetup remove_all -f &>/dev/null || true
    fi
    if [[ "${lCNT}" -gt 10 ]]; then
      break
    fi
    sleep 5
  done

  local lCNT=0
  while (! losetup -Pf "${1}"); do
    ((lCNT+=1))
    if [[ "${lCNT}" -gt 10 ]]; then
      break
    fi
    sleep 5
  done

  local lCNT=0
  while (! "${lFOUND}"); do
    sleep 1
    ((lCNT+=1))
    local lLOSETUP_OUT_ARR=()
    mapfile -t lLOSETUP_OUT_ARR < <(losetup | grep -v "BACK-FILE" || true)
    local lLINE=""
    for lLINE in "${lLOSETUP_OUT_ARR[@]}"; do
      lIMAGE_PATH=$(echo "${lLINE}" | awk '{print $6}')
      if [[ "${lIMAGE_PATH}" == "${1}" ]]; then
        lDEV_PATH=$(echo "${lLINE}" | awk '{print $1}')
        if [[ "$(dirname "${lDEV_PATH}")" == "/dev/loop" ]]; then
          # if we have the new naming like /dev/loop/0 -> dirname results in /dev/loop
          lDEV_NR=$(echo "${lDEV_PATH}" | rev | cut -d '/' -f1 | rev)
          lDEV_PATH="/dev/loop${lDEV_NR}p1"
        else
          # old naming like /dev/loop0 -> dirname results in /dev/
          lDEV_PATH=$(echo "${lLINE}" | awk '{print $1}')p1
        fi
        if [[ -b "${lDEV_PATH}" ]]; then
          lFOUND=true
        fi
      fi
    done
    if [[ "${lCNT}" -gt 600 ]]; then
      # get an exit if nothing happens
      break
    fi
  done

  if [[ "${lDEV_PATH}" != "NA" ]]; then
    local lCNT=0
    while (! find "${lDEV_PATH}" -ls 2>/dev/null | grep -q "disk"); do
      sleep 1
      ((lCNT+=1))
      if [[ "${lCNT}" -gt 600 ]]; then
        # get an exit if nothing happens
        break
      fi
    done
  fi
  echo "${lDEV_PATH}"
}

get_kernel_version() {
  local lKV=""
  local lKERNELV_ARR=()

  if [[ -f "${S25_LOG}" ]]; then
    mapfile -t lKERNELV_ARR < <(grep "Statistics:" "${S25_LOG}" | cut -d: -f2 | sort -u || true)
    if [[ -v lKERNELV_ARR[@] ]]; then
      # if we have found a kernel it is a Linux system:$
      for lKV in "${lKERNELV_ARR[@]}"; do
        if [[ "${lKV}" == "2"* ]]; then
          KERNEL_V=2
          break
        elif [[ "${lKV}" == "4"* ]]; then
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
  local lIP_ADDRESS="${1:-192.168.0.1}"
  local lNETWORK_MODE="${2:-bridge}"
  local lNETWORK_DEVICE="${3:-br0}"
  local lETH_INT="${4:-eth0}"

  echo "${lNETWORK_MODE}" > "${MNT_POINT}/firmadyne/network_type"
  echo "${lNETWORK_DEVICE}" > "${MNT_POINT}/firmadyne/net_bridge"
  echo "${lETH_INT}" > "${MNT_POINT}/firmadyne/net_interface"
  if [[ -z "${lIP_ADDRESS}" ]]; then
    lIP_ADDRESS="192.168.0.1"
  fi
  echo "${lIP_ADDRESS}" > "${MNT_POINT}/firmadyne/ip_default"
}

write_results() {
  if [[ "${IN_DOCKER}" -eq 1 ]] && [[ -f "${TMP_DIR}"/fw_name.log ]]; then
    local lFIRMWARE_PATH_orig=""
    lFIRMWARE_PATH_orig="$(cat "${TMP_DIR}"/fw_name.log)"
  fi

  local lARCHIVE_PATH="${1:-}"
  local lR_PATH="${2:-}"
  local lRESULT_SOURCE="${3:-}"
  local lNETWORK_MODE="${4:-}"
  local lETH_INT="${5:-}"
  local lVLAN_ID="${6:-}"
  local lINIT_FILE="${7:-}"
  local lNETWORK_DEVICE="${8:-}"

  local lR_PATH_mod=""
  lR_PATH_mod="${lR_PATH/${LOG_DIR}/}"
  local lTCP_SERV_CNT=0

  lTCP_SERV_CNT="$(grep -h "udp.*open\ \|tcp.*open\ " "${ARCHIVE_PATH}"/*"${NMAP_LOG}" 2>/dev/null | awk '{print $1}' | sort -u | wc -l || true)"

  [[ "${lTCP_SERV_CNT}" -gt 0 ]] && TCP="ok"
  lARCHIVE_PATH="$(echo "${lARCHIVE_PATH}" | rev | cut -d '/' -f1 | rev)"
  if ! [[ -f "${L10_SYS_EMU_RESULTS}" ]]; then
    write_log "FIRMWARE_PATH;RESULT_SOURCE;Booted state;ICMP state;TCP-0 state;TCP state;online services;IP address;Network mode (NETWORK_DEVICE|ETH_INT|VLAN_ID|INIT_FILE|INIT_MECHANISM);ARCHIVE_PATH_;R_PATH" "${L10_SYS_EMU_RESULTS}"
  fi
  write_log "${lFIRMWARE_PATH_orig:-NA};${lRESULT_SOURCE};Booted ${BOOTED};ICMP ${ICMP};TCP-0 ${TCP_0};TCP ${TCP};${lTCP_SERV_CNT};IP address: ${IP_ADDRESS_};Network mode: ${lNETWORK_MODE} (${lNETWORK_DEVICE}|${lETH_INT}|${lVLAN_ID}|${lINIT_FILE}|${KINIT/=*});${lARCHIVE_PATH};${lR_PATH_mod}" "${L10_SYS_EMU_RESULTS}"
  print_bar ""
}

set_firmae_arbitration() {
  local lFIRMAE_STATE="${1:-true}"
  # FirmAE arbitration - enable all mechanisms
  export EMBA_BOOT="${lFIRMAE_STATE}"
  export EMBA_NET="${lFIRMAE_STATE}"
  export EMBA_NVRAM="${lFIRMAE_STATE}"
  export EMBA_KERNEL="${lFIRMAE_STATE}"
  export EMBA_ETC="${lFIRMAE_STATE}"
}

color_qemu_log() {
  local lQEMU_LOG_FILE="${1:-}"
  if ! [[ -f "${lQEMU_LOG_FILE:-}" ]]; then
    return
  fi

  # GREEN: keywords for network identification:
  sed -i -r "s/.*br_add_if.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*br_dev_ioctl.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*__inet_insert_ifa.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*ioctl_SIOCSIFHWADDR.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*register_vlan_dev.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*\[NVRAM\]\ .*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*inet_bind.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*adding VLAN [0-9] to HW filter on device eth[0-9].*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"

  # Green: other interesting areas:
  sed -i -r "s/.*Kernel\ command\ line:\ .*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*Starting\ services\ in\ emulated\ environment.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*Network configuration - ACTION.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*starting\ network\ configuration.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*Current\ network\ configuration.*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*Netstat\ output\ .*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"
  sed -i -r "s/.*Starting\ .*\ service\ .*/\x1b[32m&\x1b[0m/" "${lQEMU_LOG_FILE}"

  # RED:
  sed -i -r "s/.*Kernel\ panic\ -\ .*/\x1b[31m&\x1b[0m/" "${lQEMU_LOG_FILE}"
}

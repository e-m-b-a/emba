#!/bin/bash -p

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
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Emulates executables from the firmware with qemu to get version information.
#               Currently this is an experimental module and needs to be activated separately via the -E switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

S115_usermode_emulator() {
  local lNEG_LOG=0

  module_log_init "${FUNCNAME[0]}"
  module_title "Qemu user-mode emulation"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ "${QEMULATION}" -eq 1 && "${RTOS}" -eq 0 ]]; then

    if [[ ${IN_DOCKER} -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode as it could harm your host environment."
    fi

    export OPTS=()
    if [[ "${ARCH}" != "MIPS64" ]] && command -v jchroot > /dev/null; then
      # we have seen issues on MIPS64 -> lets fall back to chroot
      setup_jchroot
    elif command -v chroot > /dev/null; then
      setup_chroot
    else
      print_output "[-] No chroot binary found ..."
      module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
      return
    fi

    local lEMULATOR="NA"
    local lBIN_EMU_ARR=()
    local lBIN_EMU_TMP_ARR=()
    local lWAIT_PIDS_S115_ARR=()
    local lMAX_THREADS_S115=1
    local lBINARY=""
    local lBIN_FILE=""
    local lBIN_BLACKLIST_ARR=()
    export MISSING_AREAS_ARR=()
    export ROOT_CNT=0

    print_output "[*] This module creates a working copy of the firmware filesystem in the log directory ${LOG_DIR}.\\n"
    # get the local interface ip address for later verification
    # ensure that the emulator does not reconfigure the interface
    get_local_ip

    # load blacklist of binaries that could cause troubles during emulation:
    readarray -t lBIN_BLACKLIST_ARR < "${CONFIG_DIR}"/emulation_blacklist.cfg

    # as we modify the firmware area, we copy it to the log directory and do the modifications in this area
    copy_firmware

    detect_root_dir_helper "${EMULATION_PATH_BASE}"

    print_output "[*] Detected ${ORANGE}${#ROOT_PATH[@]}${NC} root directories"

    kill_qemu_threader &
    export PID_killer="$!"
    disown "${PID_killer}" 2> /dev/null || true

    for R_PATH in "${ROOT_PATH[@]}" ; do
      print_ln
      lNEG_LOG=1
      print_output "[*] Detected root path: ${ORANGE}${R_PATH}${NC}"
      if [[ -f "${HELP_DIR}"/fix_bins_lnk_emulation.sh ]] && [[ $(find "${R_PATH}" -type l | wc -l) -lt 10 ]]; then
        print_output "[*] No symlinks found in firmware ... Starting link fixing helper ..."
        "${HELP_DIR}"/fix_bins_lnk_emulation.sh "${R_PATH}"
      fi
      # lMD5_DONE_INT_ARR is the array of all MD5 checksums for all root paths -> this is needed to ensure that we do not test bins twice
      local lMD5_DONE_INT_ARR=()
      local lBIN_CNT=0
      ((ROOT_CNT=ROOT_CNT+1))
      print_output "[*] Running emulation processes in ${ORANGE}${R_PATH}${NC} root path (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})."

      local lDIR=""
      lDIR=$(pwd)
      mapfile -t lBIN_EMU_TMP_ARR < <(cd "${R_PATH}" && find . -xdev -ignore_readdir_race -type f ! \( -name "*.ko" -o -name "*.so" -o -name "*.raw" \) -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" 2>/dev/null | grep "ELF.*executable\|ELF.*shared\ object" | grep -v "version\ .\ (FreeBSD)" | cut -d: -f1 2>/dev/null' && cd "${lDIR}" || exit)
      # we re-create the lBIN_EMU_ARR array with all unique binaries for every root directory
      # as we have all tested MD5s in lMD5_DONE_INT_ARR (for all root dirs) we test every bin only once
      lBIN_EMU_ARR=()

      print_output "[*] Create unique binary array for ${ORANGE}${R_PATH}${NC} root path (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})."

      for lBINARY in "${lBIN_EMU_TMP_ARR[@]}"; do
        # we emulate every binary only once. So calculate the checksum and store it for checking
        local lBIN_MD5_=""
        lBIN_MD5_=$(md5sum "${R_PATH}"/"${lBINARY}" | cut -d\  -f1)

        # if we have already some SBOM json we check if we have already create some entry with version for this binary
        # to do this, we remove unhandled_file entries
        if [[ -d "${SBOM_LOG_PATH}" ]]; then
          if grep -lr '"alg":"MD5","content":"'"${lBIN_MD5_}" "${SBOM_LOG_PATH}"/* | grep -qv "unhandled_file"; then
            print_output "[*] Already found SBOM results for ${lBINARY} ... skip emulation tests" "no_log"
            continue
          fi
        fi
        if [[ ! " ${lMD5_DONE_INT_ARR[*]} " =~ ${lBIN_MD5_} ]]; then
          lBIN_EMU_ARR+=( "${lBINARY}" )
          lMD5_DONE_INT_ARR+=( "${lBIN_MD5_}" )
        fi
      done

      print_output "[*] Testing ${ORANGE}${#lBIN_EMU_ARR[@]}${NC} unique executables in root directory: ${ORANGE}${R_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})."

      local lCPU_CNT=1
      lCPU_CNT="$(nproc || echo 1)"

      for BIN_ in "${lBIN_EMU_ARR[@]}" ; do
        ((lBIN_CNT=lBIN_CNT+1))
        FULL_BIN_PATH="${R_PATH}"/"${BIN_}"

        local lBIN_EMU_NAME_=""
        lBIN_EMU_NAME_=$(basename "${FULL_BIN_PATH}")

        local lTHOLD=0
        lTHOLD=$(( 25*"${ROOT_CNT}" ))
        # if we have already a log file with a lot of content we assume this binary was already emulated correct
        if [[ $(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "${LOG_DIR}"/s115_usermode_emulator/qemu_init_"${lBIN_EMU_NAME_}".txt 2>/dev/null | grep -c -v -E "\[\*\]\ " || true) -gt "${lTHOLD}" ]]; then
          print_output "[!] BIN ${lBIN_EMU_NAME_} was already emulated ... skipping"
          continue
        fi

        if echo "${lBIN_BLACKLIST_ARR[@]}" | grep -q -F -w "${lBIN_EMU_NAME_}"; then
          print_output "[*] Binary ${ORANGE}${BIN_}${NC} (${ORANGE}${lBIN_CNT}/${#lBIN_EMU_ARR[@]}${NC}) not emulated - blacklist triggered"
          continue
        else
          if [[ "${THREADED}" -eq 1 ]]; then
            # we adjust the max threads regularly. S115 respects the consumption of S09 and adjusts the threads
            lMAX_THREADS_S115=$((5*"${lCPU_CNT:-1}"))
            if [[ $(grep -i -c S09_ "${LOG_DIR}"/"${MAIN_LOG_FILE}" || true) -eq 1 ]]; then
              # if only one result for S09_ is found in emba.log means the S09 module is started and currently running
              lMAX_THREADS_S115=$((3*"${lCPU_CNT:-1}"))
            fi
          fi
          if [[ "${BIN_}" != './qemu-'*'-static' ]]; then
            lBIN_FILE=$(file -b "${FULL_BIN_PATH}")
            if [[ "${lBIN_FILE}" =~ version\ .\ (FreeBSD) ]]; then
              # https://superuser.com/questions/1404806/running-a-freebsd-binary-on-linux-using-qemu-user
              print_output "[-] No working emulator found for FreeBSD binary ${ORANGE}${BIN_}${NC}."
              lEMULATOR="NA"
              continue
            elif [[ "${lBIN_FILE}" == *"x86-64"* ]]; then
              lEMULATOR="qemu-x86_64-static"
            elif [[ "${lBIN_FILE}" =~ Intel\ 80386 ]]; then
              lEMULATOR="qemu-i386-static"
            elif [[ "${lBIN_FILE}" =~ Intel\ i386 ]]; then
              lEMULATOR="qemu-i386-static"
            elif [[ "${lBIN_FILE}" =~ 32-bit\ LSB.*ARM ]]; then
              lEMULATOR="qemu-arm-static"
            elif [[ "${lBIN_FILE}" =~ 32-bit\ MSB.*ARM ]]; then
              lEMULATOR="qemu-armeb-static"
            elif [[ "${lBIN_FILE}" =~ 64-bit\ LSB.*ARM\ aarch64 ]]; then
              lEMULATOR="qemu-aarch64-static"
            elif [[ "${lBIN_FILE}" =~ 64-bit\ MSB.*ARM\ aarch64 ]]; then
              lEMULATOR="qemu-aarch64_be-static"
            elif [[ "${lBIN_FILE}" =~ 32-bit\ LSB.*MIPS ]]; then
              lEMULATOR="qemu-mipsel-static"
            elif [[ "${lBIN_FILE}" == "ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2 version 1" ]]; then
              lEMULATOR="qemu-mipsn32-static"
            elif [[ "${lBIN_FILE}" =~ 32-bit\ MSB.*MIPS ]]; then
              lEMULATOR="qemu-mips-static"
            elif [[ "${lBIN_FILE}" =~ 64-bit\ LSB.*MIPS ]]; then
              lEMULATOR="qemu-mips64el-static"
            elif [[ "${lBIN_FILE}" =~ 64-bit\ MSB.*MIPS ]]; then
              lEMULATOR="qemu-mips64-static"
            elif [[ "${lBIN_FILE}" =~ 32-bit\ MSB.*PowerPC ]]; then
              lEMULATOR="qemu-ppc-static"
            elif [[ "${lBIN_FILE}" == *"ELF 32-bit LSB executable, Altera Nios II"* ]]; then
              # the latest qemu package from kali does not include the nios2 emulator anymore
              lEMULATOR="qemu-nios2-static"
              if ! command -v "${lEMULATOR}" > /dev/null; then
                print_output "[-] No working NIOS2 emulator found for ${BIN_}"
                continue
              fi
            elif [[ "${lBIN_FILE}" == *"ELF 32-bit LSB shared object, Altera Nios II"* ]]; then
              # the latest qemu package from kali does not include the nios2 emulator anymore
              lEMULATOR="qemu-nios2-static"
              if ! command -v "${lEMULATOR}" > /dev/null; then
                print_output "[-] No working NIOS2 emulator found for ${BIN_}"
                continue
              fi
            elif [[ "${lBIN_FILE}" == *"ELF 32-bit LSB executable, QUALCOMM DSP6"* ]]; then
              lEMULATOR="qemu-hexagon-static"
            elif [[ "${lBIN_FILE}" == *"ELF 32-bit LSB shared object, QUALCOMM DSP6"* ]]; then
              lEMULATOR="qemu-hexagon-static"
            else
              print_output "[-] No working emulator found for ${BIN_}"
              lEMULATOR="NA"
              continue
            fi

            if [[ "${lEMULATOR}" != "NA" ]]; then
              prepare_emulator "${R_PATH}" "${lEMULATOR}"
              if [[ "${THREADED}" -eq 1 ]]; then
                emulate_binary "${lEMULATOR}" "${R_PATH}" "${BIN_}" &
                local lTMP_PID="$!"
                store_kill_pids "${lTMP_PID}"
                write_pid_log "${FUNCNAME[0]} - emulate_binary - ${BIN_} - ${lTMP_PID}"
                lWAIT_PIDS_S115_ARR+=( "${lTMP_PID}" )
                max_pids_protection "${lMAX_THREADS_S115}" lWAIT_PIDS_S115_ARR
              else
                emulate_binary "${lEMULATOR}" "${R_PATH}" "${BIN_}"
              fi
            fi
          fi
          running_jobs "${lEMULATOR}"
        fi
      done
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S115_ARR[@]}"

    s115_cleanup "${lEMULATOR}"
    running_jobs "${lEMULATOR}"
    print_filesystem_fixes
    recover_local_ip "${IP_ETH0}"

  else
    print_ln
    print_output "[!] Automated emulation is disabled."
    print_output "[!] Enable it with the ${ORANGE}-E${MAGENTA} switch.${NC}"
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

copy_firmware() {
  local lFREE_SPACE=""
  local lNEEDED_SPACE=0

  if [[ -d "${FIRMWARE_PATH_BAK}" ]]; then
    export EMULATION_PATH_BASE="${FIRMWARE_PATH}"
  else
    export EMULATION_PATH_BASE="${LOG_DIR}"/firmware
  fi

  # we create a backup copy for user mode emulation only if we have enough disk space.
  # If there is not enough disk space we use the original firmware directory
  lFREE_SPACE="$(df --output=avail "${LOG_DIR}" | awk 'NR==2')"
  lNEEDED_SPACE="$(( "$(du --max-depth=0 "${EMULATION_PATH_BASE}" | awk '{print $1}')" + 10000 ))"

  if [[ "${lFREE_SPACE}" -gt "${lNEEDED_SPACE}" ]]; then
    print_output "[*] Create a firmware backup for emulation ..."
    cp -pri "${EMULATION_PATH_BASE}" "${LOG_PATH_MODULE}"/firmware 2> /dev/null
    EMULATION_PATH_BASE="${LOG_PATH_MODULE}"/firmware
    print_output "[*] Firmware backup for emulation created in ${ORANGE}${EMULATION_PATH_BASE}${NC}"
  else
    print_output "[!] WARNING: Not enough disk space available - we do not create a firmware backup for emulation ..."
    EMULATION_PATH_BASE="${LOG_DIR}"/firmware
    print_output "[*] Firmware used for emulation in ${ORANGE}${EMULATION_PATH_BASE}${NC}"
  fi
}

setup_jchroot() {
  export CHROOT="jchroot"
  export OPTS=()
  echo "${CHROOT}" > "${TMP_DIR}"/chroot_mode.tmp
  # if [[ "${IN_DOCKER}" -eq 1 ]]; then
  #  # OPTS see https://github.com/vincentbernat/jchroot#security-note
  #  OPTS=(-U -u 0 -g 0 -M "0 $(id -u) 1" -G "0 $(id -g) 1")
  # fi
  print_output "[*] Using ${ORANGE}jchroot${NC} for building more secure chroot environments"
}

setup_chroot() {
  export OPTS=()
  export CHROOT="chroot"
  echo "${CHROOT}" > "${TMP_DIR}"/chroot_mode.tmp
  print_output "[*] Using ${ORANGE}chroot${NC} for building chroot environments"
}

prepare_emulator() {
  local lR_PATH="${1:-}"
  local lEMULATOR="${2:-}"

  if [[ ! -e "${lR_PATH}""/""${lEMULATOR}" ]]; then

    sub_module_title "Preparation phase"

    print_output "[*] Preparing the environment for usermode emulation"
    if ! command -v "${lEMULATOR}" > /dev/null ; then
      print_ln "no_log"
      print_output "[!] Is the qemu package installed?"
      print_output "$(indent "We can't find it!")"
      print_output "$(indent "$(red "Terminating Emulation module now.\\n")")"
      exit 1
    else
      cp "$(command -v "${lEMULATOR}")" "${lR_PATH}" || (print_output "[-] Issues in copy emulator process for emulator ${lEMULATOR}" && return)
    fi

    if ! [[ -d "${lR_PATH}""/proc" ]] ; then
      mkdir "${lR_PATH}""/proc" 2> /dev/null || true
    fi

    if ! [[ -d "${lR_PATH}""/sys" ]] ; then
      mkdir "${lR_PATH}""/sys" 2> /dev/null || true
    fi

    if ! [[ -d "${lR_PATH}""/run" ]] ; then
      mkdir "${lR_PATH}""/run" 2> /dev/null || true
    fi

    if ! [[ -d "${lR_PATH}""/dev/" ]] ; then
      mkdir "${lR_PATH}""/dev/" 2> /dev/null || true
    fi

    if ! mount | grep "${lR_PATH}"/proc > /dev/null ; then
      mount proc "${lR_PATH}""/proc" -t proc 2> /dev/null || true
    fi
    if ! mount | grep "${lR_PATH}/run" > /dev/null ; then
      mount -o bind /run "${lR_PATH}""/run" 2> /dev/null || true
    fi
    if ! mount | grep "${lR_PATH}/sys" > /dev/null ; then
      mount -o bind /sys "${lR_PATH}""/sys" 2> /dev/null || true
    fi

    creating_dev_area "${lR_PATH}"

    print_ln
    print_output "[*] Currently mounted areas:"
    print_output "$(indent "$(mount | grep "${lR_PATH}" 2> /dev/null || true)")""\\n"

    print_output "[*] Final fixes of the root filesytem in a chroot environment"
    cp "${HELP_DIR}"/fixImage_user_mode_emulation.sh "${lR_PATH}"
    chmod +x "${lR_PATH}"/fixImage_user_mode_emulation.sh
    cp "$(command -v busybox)" "${lR_PATH}"
    chmod +x "${lR_PATH}"/busybox
    if [[ "${CHROOT}" == "jchroot" ]]; then
      "${CHROOT}" "${OPTS[@]}" "${lR_PATH}" -- /busybox ash /fixImage_user_mode_emulation.sh | tee -a "${LOG_PATH_MODULE}"/chroot_fixes.txt || print_error "[-] Something weird going wrong in jchroot filesystem fixing for ${lR_PATH}"
    else
      "${CHROOT}" "${OPTS[@]}" "${lR_PATH}" /busybox ash /fixImage_user_mode_emulation.sh | tee -a "${LOG_PATH_MODULE}"/chroot_fixes.txt || print_error "[-] Something weird going wrong in chroot filesystem fixing for ${lR_PATH}"
    fi
    rm "${lR_PATH}"/fixImage_user_mode_emulation.sh || true
    rm "${lR_PATH}"/busybox || true
    print_bar
  fi
}

# Iterates through possible qemu CPU configs
# this is a jumper function for further processing and at the end running
# emulation with the CPU config in strace mode
run_init_test() {
  local lFULL_BIN_PATH="${1:-}"
  local lEMULATOR="${2:-}"
  local lBIN_EMU_NAME_=""
  lBIN_EMU_NAME_=$(basename "${lFULL_BIN_PATH}")
  local lLOG_FILE_INIT="${LOG_PATH_MODULE}""/qemu_init_""${lBIN_EMU_NAME_}"".txt"
  local lCPU_CONFIGS_ARR=()
  local lCPU_CONFIG=""

  write_log "\\n-----------------------------------------------------------------\\n" "${lLOG_FILE_INIT}"

  # get the most used cpu configuration for the initial check:
  if [[ -f "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" ]]; then
    lCPU_CONFIG=$(grep -a CPU_CONFIG "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" | cut -d\; -f2 | uniq -c | sort -nr | head -1 | awk '{print $2}' || true)
  fi

  print_output "[*] Initial CPU detection process of binary ${ORANGE}${lBIN_EMU_NAME_}${NC} with CPU configuration ${ORANGE}${lCPU_CONFIG}${NC}." "${lLOG_FILE_INIT}" "${lLOG_FILE_INIT}"
  write_log "[*] Emulator used: ${ORANGE}${lEMULATOR}${NC}" "${lLOG_FILE_INIT}"
  write_log "[*] Using root directory: ${ORANGE}${R_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})" "${lLOG_FILE_INIT}"
  write_log "" "${lLOG_FILE_INIT}"

  # this is an initial jchroot check. If this fails we switch back to chroot via "setup_chroot"
  if [[ "${CHROOT}" == "jchroot" ]]; then
    timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${lEMULATOR}" --strace "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_chroot_check_""${lBIN_EMU_NAME_}"".txt" 2>&1 || true
    local lPID="$!"
    disown "${lPID}" 2> /dev/null || true
    if [[ -f "${LOG_PATH_MODULE}""/qemu_chroot_check_""${lBIN_EMU_NAME_}"".txt" ]] && grep -q "unable to create temporary directory for pivot root: Permission denied" "${LOG_PATH_MODULE}""/qemu_chroot_check_""${lBIN_EMU_NAME_}"".txt"; then
      print_output "[*] jchroot issues identified - ${ORANGE}switching to chroot${NC}" "no_log"
      setup_chroot
    fi
    if [[ -f "${LOG_PATH_MODULE}""/qemu_chroot_check_""${lBIN_EMU_NAME_}"".txt" ]]; then
      rm "${LOG_PATH_MODULE}""/qemu_chroot_check_""${lBIN_EMU_NAME_}"".txt" || true
    fi
  fi
  run_init_qemu "${lCPU_CONFIG}" "${lBIN_EMU_NAME_}" "${lLOG_FILE_INIT}" "${lEMULATOR}"

  if [[ ! -f "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" || $(grep -a -c "Illegal instruction\|cpu_init.*failed" "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" 2> /dev/null) -gt 0 || $(wc -l < "${LOG_PATH_MODULE}/qemu_initx_${lBIN_EMU_NAME_}.txt") -lt 6 ]]; then

    write_log "[-] Emulation process of binary ${ORANGE}${lBIN_EMU_NAME_}${NC} with CPU configuration ${ORANGE}${lCPU_CONFIG}${NC} failed" "${lLOG_FILE_INIT}"

    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      mapfile -t lCPU_CONFIGS_ARR < <("${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${lEMULATOR}" -cpu help | grep -v alias | awk '{print $2}' | tr -d "'" || true)
    else
      mapfile -t lCPU_CONFIGS_ARR < <("${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${lEMULATOR}" -cpu help | grep -v alias | awk '{print $2}' | tr -d "'" || true)
    fi

    for lCPU_CONFIG in "${lCPU_CONFIGS_ARR[@]}"; do
      if [[ -f "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" ]]; then
        rm "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" || true
      fi

      run_init_qemu "${lCPU_CONFIG}" "${lBIN_EMU_NAME_}" "${lLOG_FILE_INIT}" "${lEMULATOR}"

      if [[ -z "${lCPU_CONFIG}" ]]; then
        lCPU_CONFIG="NONE"
      fi

      if [[ ! -f "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" || $(grep -a -c "Illegal instruction\|cpu_init.*failed" "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" 2> /dev/null) -gt 0 || $(wc -l < "${LOG_PATH_MODULE}/qemu_initx_${lBIN_EMU_NAME_}.txt") -lt 6 ]]; then
        write_log "[-] Emulation process of binary ${ORANGE}${lBIN_EMU_NAME_}${NC} with CPU configuration ${ORANGE}${lCPU_CONFIG}${NC} failed" "${lLOG_FILE_INIT}"
        continue
      fi

      write_log "" "${lLOG_FILE_INIT}"
      write_log "[+] CPU configuration used for ${ORANGE}${lBIN_EMU_NAME_}${GREEN}: ${ORANGE}${lCPU_CONFIG}${GREEN}" "${lLOG_FILE_INIT}"
      write_log "CPU_CONFIG_det\;${lCPU_CONFIG}" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"
      write_log "CPU_CONFIG_det\;${lCPU_CONFIG}" "${lLOG_FILE_INIT}"
      break

    done
  else
    [[ -z "${lCPU_CONFIG}" ]] && lCPU_CONFIG="NONE"

    write_log "[+] CPU configuration used for ${ORANGE}${lBIN_EMU_NAME_}${GREEN}: ${ORANGE}${lCPU_CONFIG}${GREEN}" "${lLOG_FILE_INIT}"
    write_log "CPU_CONFIG_det\;${lCPU_CONFIG}" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"
    write_log "CPU_CONFIG_det\;${lCPU_CONFIG}" "${lLOG_FILE_INIT}"
  fi

  # fallback solution - we use the most working configuration:
  if [[ -f "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" ]] && ! grep -q "CPU_CONFIG_det" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"; then
    lCPU_CONFIG=$(grep -a CPU_CONFIG "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" | cut -d\; -f2 | uniq -c | sort -nr | head -1 | awk '{print $2}' || true)
    write_log "[+] CPU configuration used for ${ORANGE}${lBIN_EMU_NAME_}${GREEN}: ${ORANGE}${lCPU_CONFIG}${GREEN}" "${lLOG_FILE_INIT}"
    write_log "CPU_CONFIG_det\;${lCPU_CONFIG}" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"
    write_log "CPU_CONFIG_det\;${lCPU_CONFIG}" "${lLOG_FILE_INIT}"
    write_log "[*] Fallback to most found CPU configuration" "${lLOG_FILE_INIT}"
  fi
  sed -i 's/.REF.*//' "${lLOG_FILE_INIT}"
  write_log "\\n-----------------------------------------------------------------\\n" "${lLOG_FILE_INIT}"
}

# jump function for run_init_qemu_runner -> runs emulation process with stracer
# The goal is to find a working CPU configuration for qemu
run_init_qemu() {
  local lCPU_CONFIG="${1:-}"
  local lBIN_EMU_NAME_="${2:-}"
  local lLOG_FILE_INIT="${3:-}"
  local lEMULATOR="${4:-}"

  # Enable the following echo output for debugging
  # echo "BIN: $BIN_" | tee -a "${lLOG_FILE_INIT}"
  # echo "lEMULATOR: $lEMULATOR" | tee -a "${lLOG_FILE_INIT}"
  # echo "R_PATH: $R_PATH" | tee -a "${lLOG_FILE_INIT}"
  # echo "CPU_CONFIG: $lCPU_CONFIG" | tee -a "${lLOG_FILE_INIT}"

  [[ "${STRICT_MODE}" -eq 1 ]] && set +e
  run_init_qemu_runner "${lCPU_CONFIG}" "${lBIN_EMU_NAME_}" "${lLOG_FILE_INIT}" "${lEMULATOR}" &
  local lPID=$!
  write_pid_log "${FUNCNAME[0]} - runner - ${BIN_} - ${lPID}"
  [[ "${STRICT_MODE}" -eq 1 ]] && set -e
  disown "${lPID}" 2> /dev/null || true

  # wait a bit and then kill it
  sleep 1
  kill -9 "${lPID}" 2> /dev/null || true
  if [[ -f "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" ]]; then
    cat "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" >> "${lLOG_FILE_INIT}" || true
  fi
}

# runs emulation process with stracer - for CPU config detection
run_init_qemu_runner() {
  local lCPU_CONFIG="${1:-}"
  local lBIN_EMU_NAME_="${2:-}"
  local lLOG_FILE_INIT="${3:-}"
  local lEMULATOR="${4:-}"

  if [[ -z "${lCPU_CONFIG}" || "${lCPU_CONFIG}" == "NONE" ]]; then
    write_log "[*] Trying to emulate binary ${ORANGE}${BIN_}${NC} with cpu config ${ORANGE}NONE${NC}" "${lLOG_FILE_INIT}"
    write_log "" "${lLOG_FILE_INIT}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${lEMULATOR}" --strace "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" 2>&1 || true
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${lEMULATOR}" --strace "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" 2>&1 || true
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    fi
  else
    write_log "[*] Trying to emulate binary ${ORANGE}${BIN_}${NC} with cpu config ${ORANGE}${lCPU_CONFIG}${NC}" "${lLOG_FILE_INIT}"
    write_log "" "${lLOG_FILE_INIT}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${lEMULATOR}" --strace -cpu "${lCPU_CONFIG}" "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" 2>&1 || true
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${lEMULATOR}" --strace -cpu "${lCPU_CONFIG}" "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${lBIN_EMU_NAME_}"".txt" 2>&1 || true
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    fi
  fi
}

# runs emulation process with stracer for detection of missing filesystem areas
# the goal is to search these missing areas within the extracted firmware
# sometimes we can find them and copy to the right area
emulate_strace_run() {
  local lCPU_CONFIG="${1:-}"
  local lBIN_EMU_NAME="${2:-}"
  local lEMULATOR="${3:-}"
  local lMISSING_AREAS_TMP_ARR=()
  local lLOG_FILE_STRACER="${LOG_PATH_MODULE}""/stracer_""${lBIN_EMU_NAME}"".txt"
  local lFILENAME_MISSING=""
  local lPATH_MISSING=""
  local lFILENAME_FOUND=""

  write_log "\\n-----------------------------------------------------------------\\n" "${lLOG_FILE_STRACER}"

  print_output "[*] Initial strace run with ${ORANGE}${CHROOT}${NC} on the command ${ORANGE}${BIN_}${NC} to identify missing areas" "${lLOG_FILE_STRACER}" "${lLOG_FILE_STRACER}"
  write_log "[*] Emulating binary name: ${ORANGE}${lBIN_EMU_NAME}${NC} in ${ORANGE}strace${NC} mode to identify missing areas (with ${ORANGE}${CHROOT}${NC})" "${lLOG_FILE_STRACER}"
  write_log "[*] Emulator used: ${ORANGE}${lEMULATOR}${NC}" "${lLOG_FILE_STRACER}"
  write_log "[*] Chroot environment used: ${ORANGE}${CHROOT}${NC}" "${lLOG_FILE_STRACER}"
  write_log "[*] Using root directory: ${ORANGE}${R_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})" "${lLOG_FILE_STRACER}"
  write_log "[*] Using CPU config: ${ORANGE}${lCPU_CONFIG}${NC}" "${lLOG_FILE_STRACER}"
  write_log "" "${lLOG_FILE_STRACER}"

  # currently we only look for file errors (errno=2) and try to fix this
  [[ "${STRICT_MODE}" -eq 1 ]] && set +e
  if [[ -z "${lCPU_CONFIG}" || "${lCPU_CONFIG}" == *"NONE"* ]]; then
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${lEMULATOR}" --strace "${BIN_}" >> "${lLOG_FILE_STRACER}" 2>&1 &
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${lEMULATOR}" --strace "${BIN_}" >> "${lLOG_FILE_STRACER}" 2>&1 &
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    fi
  else
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${lEMULATOR}" -cpu "${lCPU_CONFIG}" --strace "${BIN_}" >> "${lLOG_FILE_STRACER}" 2>&1 &
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${lEMULATOR}" -cpu "${lCPU_CONFIG}" --strace "${BIN_}" >> "${lLOG_FILE_STRACER}" 2>&1 &
      local lPID="$!"
      disown "${lPID}" 2> /dev/null || true
    fi
  fi
  write_pid_log "${FUNCNAME[0]} - ${CHROOT} - ${BIN_} - ${lPID}"
  [[ "${STRICT_MODE}" -eq 1 ]] && set -e

  # wait a second and then kill it
  sleep 1
  kill -9 "${lPID}" 2> /dev/null || true

  # extract missing files, exclude *.so files:
  write_log "" "${lLOG_FILE_STRACER}"
  write_log "[*] Identification of missing filesytem areas." "${lLOG_FILE_STRACER}"

  mapfile -t MISSING_AREAS_ARR < <(grep -a "open.*errno=2\ " "${lLOG_FILE_STRACER}" 2>&1 | cut -d\" -f2 2>&1 | sort -u || true)
  mapfile -t lMISSING_AREAS_TMP_ARR < <(grep -a "^qemu.*: Could not open" "${lLOG_FILE_STRACER}" | cut -d\' -f2 2>&1 | sort -u || true)
  MISSING_AREAS_ARR+=("${lMISSING_AREAS_TMP_ARR[@]}" )

  if [[ "${#MISSING_AREAS_ARR[@]}" -gt 0 ]]; then
    for MISSING_AREA in "${MISSING_AREAS_ARR[@]}"; do
      if [[ "${MISSING_AREA}" != *"/proc/"* && "${MISSING_AREA}" != *"/sys/"* && "${MISSING_AREA}" != *"/dev/"* ]]; then
        write_log "[*] Found missing area: ${ORANGE}${MISSING_AREA}${NC}" "${lLOG_FILE_STRACER}"

        lFILENAME_MISSING=$(basename "${MISSING_AREA}")
        write_log "[*] Trying to identify this missing file: ${ORANGE}${lFILENAME_MISSING}${NC}" "${lLOG_FILE_STRACER}"
        lPATH_MISSING=$(dirname "${MISSING_AREA}")

        lFILENAME_FOUND=$(find "${EMULATION_PATH_BASE}" -xdev -ignore_readdir_race -name "${lFILENAME_MISSING}" 2>/dev/null | sort -u | head -1 || true)
        if [[ "${lFILENAME_FOUND}" == *"/proc/"* || "${lFILENAME_FOUND}" == *"/sys/"* || "${lFILENAME_FOUND}" == *"/dev/"* ]]; then
          continue
        fi
        if [[ -n "${lFILENAME_FOUND}" ]]; then
          write_log "[*] Possible matching file found: ${ORANGE}${lFILENAME_FOUND}${NC}" "${lLOG_FILE_STRACER}"
        fi

        if [[ ! -d "${R_PATH}""${lPATH_MISSING}" ]]; then
          write_log "[*] Creating directory ${ORANGE}${R_PATH}${lPATH_MISSING}${NC}" "${lLOG_FILE_STRACER}"
          mkdir -p "${R_PATH}""${lPATH_MISSING}" 2> /dev/null || true
          # continue
        fi
        if [[ -n "${lFILENAME_FOUND}" ]]; then
          write_log "[*] Copy file ${ORANGE}${lFILENAME_FOUND}${NC} to ${ORANGE}${R_PATH}${lPATH_MISSING}/${NC}" "${lLOG_FILE_STRACER}"
          local lOUTPUT=""
          lOUTPUT=$(file -b "${lFILENAME_FOUND}")
          if [[ "${lOUTPUT}" != *"(named pipe)" ]];then
            cp -L "${lFILENAME_FOUND}" "${R_PATH}""${lPATH_MISSING}" 2> /dev/null || true
          fi
          continue
        else
        #  # disabled this for now - have to rethink this feature
        #  # This can only be used on non library and non elf files. How can we identify them without knowing them?
        #  write_log "[*] Creating empty file $ORANGE$R_PATH$lPATH_MISSING/$lFILENAME_MISSING$NC" "${lLOG_FILE_STRACER}"
        #  touch "${R_PATH}""${lPATH_MISSING}"/"${lFILENAME_MISSING}" 2> /dev/null
          write_log "[*] Missing file ${ORANGE}${R_PATH}${lPATH_MISSING}/${lFILENAME_MISSING}${NC}" "${lLOG_FILE_STRACER}"
          continue
        fi
      fi
    done
  else
    write_log "[*] No missing areas found." "${lLOG_FILE_STRACER}"
  fi

  if [[ -f "${lLOG_FILE_STRACER}" ]]; then
    # remove the REF entries for printing the log file to the screen
    sed -i 's/.REF.*//' "${lLOG_FILE_STRACER}"
    # print it to the screen - we already have the output in the right log file
    cat "${lLOG_FILE_STRACER}" || true
    write_log "\\n-----------------------------------------------------------------\\n" "${lLOG_FILE_STRACER}"
  fi
}

emulate_binary() {
  local lEMULATOR="${1:-}"
  local lR_PATH="${2:-}"
  local lBINARY_MIN_PATH="${3:-}"

  FULL_BIN_PATH="${lR_PATH}"/"${lBINARY_MIN_PATH}"

  if ! [[ -f "${FULL_BIN_PATH}" ]]; then
    print_output "[-] ${ORANGE}${FULL_BIN_PATH}${NC} not found"
    return
  fi

  local lEMULATION_PARAMS_ARR=()
  local lPARAM=""

  local lBIN_EMU_NAME=""
  lBIN_EMU_NAME=$(basename "${FULL_BIN_PATH}")
  local lLOG_FILE_BIN="${LOG_PATH_MODULE}""/qemu_tmp_""${lBIN_EMU_NAME}"".txt"

  run_init_test "${FULL_BIN_PATH}" "${lEMULATOR}"
  # now we should have CPU_CONFIG in log file from Binary

  local lCPU_CONFIG=""
  lCPU_CONFIG="$(grep -a "CPU_CONFIG_det" "${LOG_PATH_MODULE}""/qemu_init_""${lBIN_EMU_NAME}"".txt" | cut -d\; -f2 | sort -u | head -1 || true)"

  write_log "\\n-----------------------------------------------------------------\\n" "${lLOG_FILE_BIN}"
  write_log "[*] Emulating binary name: ${ORANGE}${lBIN_EMU_NAME}${NC}" "${lLOG_FILE_BIN}"
  write_log "[*] Emulator used: ${ORANGE}${lEMULATOR}${NC}" "${lLOG_FILE_BIN}"
  write_log "[*] Using root directory: ${ORANGE}${lR_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})" "${lLOG_FILE_BIN}"
  write_log "[*] Using CPU config: ${ORANGE}${lCPU_CONFIG}${NC}" "${lLOG_FILE_BIN}"
  # write_log "[*] Root path used: $ORANGE$lR_PATH$NC" "${lLOG_FILE_BIN}"
  write_log "[*] Emulating binary: ${ORANGE}${lBINARY_MIN_PATH/\.}${NC}" "${lLOG_FILE_BIN}"
  write_log "" "${lLOG_FILE_BIN}"

  # lets assume we now have only ELF files. Sometimes the permissions of firmware updates are completely weird
  # we are going to give all ELF files exec permissions to execute it in the emulator
  if ! [[ -x "${FULL_BIN_PATH}" ]]; then
    write_log "[*] Change permissions +x to ${ORANGE}${FULL_BIN_PATH}${NC}." "${lLOG_FILE_BIN}"
    chmod +x "${FULL_BIN_PATH}"
  fi
  emulate_strace_run "${lCPU_CONFIG}" "${lBIN_EMU_NAME}" "${lEMULATOR}"

  # emulate binary with different command line parameters:
  if [[ "${lBINARY_MIN_PATH}" == *"bash"* ]]; then
    lEMULATION_PARAMS_ARR=("--help" "--version")
  else
    lEMULATION_PARAMS_ARR=("" "-v" "-V" "-h" "-help" "--help" "--version" "version")
  fi

  for lPARAM in "${lEMULATION_PARAMS_ARR[@]}"; do
    [[ -z "${lPARAM}" ]] && lPARAM="NONE"

    [[ "${STRICT_MODE}" -eq 1 ]] && set +e
    if [[ -z "${lCPU_CONFIG}" ]] || [[ "${lCPU_CONFIG}" == "NONE" ]]; then
      write_log "[*] Emulating binary ${ORANGE}${lBINARY_MIN_PATH}${NC} with parameter ${ORANGE}${lPARAM}${NC}" "${lLOG_FILE_BIN}"
      if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${lR_PATH}" -- ./"${lEMULATOR}" "${lBINARY_MIN_PATH}" "${lPARAM}" &>> "${lLOG_FILE_BIN}" || true &
        local lPID="$!"
        disown "${lPID}" 2> /dev/null || true
      else
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${lR_PATH}" ./"${lEMULATOR}" "${lBINARY_MIN_PATH}" "${lPARAM}" &>> "${lLOG_FILE_BIN}" || true &
        local lPID="$!"
        disown "${lPID}" 2> /dev/null || true
      fi
    else
      write_log "[*] Emulating binary ${ORANGE}${lBINARY_MIN_PATH}${NC} with parameter ${ORANGE}${lPARAM}${NC} and cpu configuration ${ORANGE}${lCPU_CONFIG}${NC}" "${lLOG_FILE_BIN}"
      if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${lR_PATH}" -- ./"${lEMULATOR}" -cpu "${lCPU_CONFIG}" "${lBINARY_MIN_PATH}" "${lPARAM}" &>> "${lLOG_FILE_BIN}" || true &
        local lPID="$!"
        disown "${lPID}" 2> /dev/null || true
      else
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${lR_PATH}" ./"${lEMULATOR}" -cpu "${lCPU_CONFIG}" "${lBINARY_MIN_PATH}" "${lPARAM}" &>> "${lLOG_FILE_BIN}" || true &
        local lPID="$!"
        disown "${lPID}" 2> /dev/null || true
      fi
    fi
    write_pid_log "${FUNCNAME[0]} - ${CHROOT} qemu final run - ${lBINARY_MIN_PATH} - ${lPID}"
    [[ "${STRICT_MODE}" -eq 1 ]] && set -e
    check_disk_space_emu "${lEMULATOR}"
  done

  # now we kill all older qemu-processes:
  # if we use the correct identifier $lEMULATOR it will not work ...
  # This is very ugly and should only be used in docker environment!
  pkill -9 -O "${QRUNTIME}" -f .*qemu-.*-sta.* >/dev/null || true
  write_log "\\n-----------------------------------------------------------------\\n" "${lLOG_FILE_BIN}"
  write_log "\\n\\nFor reproducing the EMBA user-mode emulation mechanism, the following commands could be used as starting point:" "${lLOG_FILE_BIN}"
  write_log "\\n - Start EMBA docker container with the firmware directory as log directory:" "${lLOG_FILE_BIN}"
  local lFW_PATH=""
  lFW_PATH=$(sort -u "${TMP_DIR}"/fw_name.log | head -1)
  write_log "      # ${ORANGE}EMBA=\".\" FIRMWARE=\"${lFW_PATH:-"/absolute/path/to/firmware"}\" LOG=\"/absolute/path/to/EMBA/log/directory\" docker-compose run emba${NC}" "${lLOG_FILE_BIN}"
  write_log "\\n - Change your working directory to the root directory of your firmware:" "${lLOG_FILE_BIN}"
  write_log "      # ${ORANGE}cd ${lR_PATH}${NC}" "${lLOG_FILE_BIN}"
  write_log "\\n - Copy the static compiled user-mode emulator to your current working directory" "${lLOG_FILE_BIN}"
  write_log "      # ${ORANGE}cp \$(which ${lEMULATOR}) .${NC}" "${lLOG_FILE_BIN}"
  if [[ -z "${lCPU_CONFIG}" ]] || [[ "${lCPU_CONFIG}" == "NONE" ]]; then
    write_log "\\n - Start the emulation with the following command: " "${lLOG_FILE_BIN}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . -- ./${lEMULATOR} ${lBINARY_MIN_PATH} <parameters like -v or --help>${NC}" "${lLOG_FILE_BIN}"
    else
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . ./${lEMULATOR} ${lBINARY_MIN_PATH} <parameters like -v or --help>${NC}" "${lLOG_FILE_BIN}"
    fi
  else
    write_log "\\n - Start the emulation with the following command: " "${lLOG_FILE_BIN}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . -- ./${lEMULATOR} -cpu ${lCPU_CONFIG} ${lBINARY_MIN_PATH} <parameters like -v or --help>${NC}" "${lLOG_FILE_BIN}"
    else
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . ./${lEMULATOR} -cpu ${lCPU_CONFIG} ${lBINARY_MIN_PATH} <parameters like -v or --help>${NC}" "${lLOG_FILE_BIN}"
    fi
  fi
  write_log "\\n${ORANGE}WARNING: EMBA is doing some more magic in the background. Probably it is not that easy, but give it a try.${NC}" "${lLOG_FILE_BIN}"
}

check_disk_space_emu() {
  local lEMULATOR="${1:-}"
  local lCRITICAL_FILES_ARR=()
  local lKILL_PROC_NAME=""

  mapfile -t lCRITICAL_FILES_ARR < <(find "${LOG_PATH_MODULE}"/ -xdev -maxdepth 1 -type f -size +"${QEMU_KILL_SIZE}" -print0 2>/dev/null |xargs -r -0 -P 16 -I % sh -c 'basename -s .txt % 2>/dev/null' || true)
  for lKILL_PROC_NAME in "${lCRITICAL_FILES_ARR[@]}"; do
    lKILL_PROC_NAME="${lKILL_PROC_NAME/qemu_tmp_}"
    lKILL_PROC_NAME="${lKILL_PROC_NAME/qemu_initx_}"
    lKILL_PROC_NAME="${lKILL_PROC_NAME/stracer_}"
    if pgrep -f "${lEMULATOR}.*${lKILL_PROC_NAME}" > /dev/null; then
      print_output "[!] Qemu processes are wasting disk space ... we try to kill it" "no_log"
      print_output "[*] Killing process ${ORANGE}${lEMULATOR}.*${lKILL_PROC_NAME}.*${NC}" "no_log"
      pkill -f "${lEMULATOR}.*${lKILL_PROC_NAME}.*" >/dev/null|| true
      # rm "${LOG_DIR}"/qemu_emulator/*"${lKILLER}"*
    fi
  done
}

running_jobs() {
  local lEMULATOR="${1:-}"
  local lCJOBS=""

  # if no emulation at all was possible the $lEMULATOR variable is not defined
  if [[ -n "${lEMULATOR}" ]]; then
    lCJOBS=$(pgrep -f -c -a "${lEMULATOR}" || true)
    if [[ -n "${lCJOBS}" ]] ; then
      print_ln "no_log"
      print_output "[*] Currently running emulation jobs: ${ORANGE}${lCJOBS}${NC}" "no_log"
    else
      lCJOBS="NA"
    fi
  fi
}

kill_qemu_threader() {
  # WARNING: This is so *** ugly! FIX IT!
  # Currently this should only used in docker environment!
  while true; do
    # print_output "[*] KILLING qemu processes" "no_log"
    pkill -9 -O 240 -f .*qemu-.*-sta.* >/dev/null || true
    sleep 20
  done
}

get_local_ip() {
  export IP_ETH0=""
  IP_ETH0=$(ifconfig eth0 2>/dev/null|awk '/inet / {print $2}')
}

recover_local_ip() {
  # some firmware images (e.g. OpenWRT) reconfigure the network interface.
  # We try to recover it now to access the CVE database
  local lIP_TO_CHECK="${1:-}"

  if ! ifconfig eth0 | grep -q "${lIP_TO_CHECK}"; then
    print_ln
    print_output "[!] Warning: The emulation process of S115 has reconfigured your network interface."
    print_output "[*] We try to recover the interface ${ORANGE}eth0${NC} with original address ${ORANGE}${lIP_TO_CHECK}${NC}"
    ifconfig eth0 "${lIP_TO_CHECK}" up
  fi
}

print_filesystem_fixes() {
  local lMISSING_FILE=""

  # MISSING_AREAS_ARR array from emulate_strace_run
  if [[ "${#MISSING_AREAS_ARR[@]}" -ne 0 ]]; then
    sub_module_title "Filesystem fixes"
    print_output "[*] EMBA has auto-generated the files during runtime."
    print_output "[*] For persistence you could generate it manually in your filesystem.\\n"
    for lMISSING_FILE in "${MISSING_AREAS_ARR[@]}"; do
      print_output "[*] Missing file: ${ORANGE}${lMISSING_FILE}${NC}"
    done
  fi
}

s115_cleanup() {
  print_ln
  sub_module_title "Cleanup phase" "no_log"
  local lEMULATOR="${1:-}"
  local lCHECK_MOUNTS_ARR=()
  local lMOUNT=""
  local lCJOBS=""
  local lLOG_FILES_ARR=()
  local lBINARY_FROM_LOG=""
  local lLOG_FILE=""

  # rm "${LOG_PATH_MODULE}""/stracer_*.txt" 2>/dev/null || true

  # if no emulation at all was possible the $lEMULATOR variable is not defined
  if [[ -n "${lEMULATOR}" ]]; then
    print_output "[*] Terminating qemu processes - check it with ps" "no_log"
    pkill -9 -f .*qemu-.*-sta.* >/dev/null || true
  fi

  lCJOBS=$(pgrep -f qemu- || true)
  if [[ -n "${lCJOBS}" ]] ; then
    print_output "[*] More emulation jobs are running ... we kill it with fire\\n" "no_log"
    pkill -9 -f .*"${lEMULATOR}".* >/dev/null || true
  fi
  kill -9 "${PID_killer}" >/dev/null || true

  print_output "[*] Cleaning the emulation environment\\n" "no_log"
  find "${EMULATION_PATH_BASE}" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null || true
  find "${EMULATION_PATH_BASE}" -xdev -iname "*.core" -exec rm {} \; 2>/dev/null || true

  print_ln "no_log"
  print_output "[*] Umounting proc, sys and run" "no_log"
  mapfile -t lCHECK_MOUNTS_ARR < <(mount | grep "${EMULATION_PATH_BASE}" || true)
  if [[ "${#lCHECK_MOUNTS_ARR[@]}" -gt 0 ]]; then
    for lMOUNT in "${lCHECK_MOUNTS_ARR[@]}"; do
      print_output "[*] Unmounting ${lMOUNT}" "no_log"
      lMOUNT=$(echo "${lMOUNT}" | cut -d\  -f3)
      umount -l "${lMOUNT}" || true
    done
  fi

  mapfile -t lLOG_FILES_ARR < <(find "${LOG_PATH_MODULE}""/" -xdev -type f -name "qemu_tmp*" 2>/dev/null)
  local lILLEGAL_INSTRUCTIONS_CNT=0
  # shellcheck disable=SC2126
  lILLEGAL_INSTRUCTIONS_CNT=$(grep -l "Illegal instruction" "${LOG_PATH_MODULE}""/"qemu_tmp* | wc -l || true)
  if [[ "${lILLEGAL_INSTRUCTIONS_CNT}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${lILLEGAL_INSTRUCTIONS_CNT}${NC}binaries not emulated - Illegal instructions" "no_log"
  fi
  if [[ "${#lLOG_FILES_ARR[@]}" -gt 0 ]] ; then
    sub_module_title "Reporting phase"
    for lLOG_FILE in "${lLOG_FILES_ARR[@]}" ; do
      local lLINES_OF_LOG=0
      lLINES_OF_LOG=$(grep -a -v -e "^[[:space:]]*$" "${lLOG_FILE}" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | \
        grep -a -v "\[\*\] " | grep -a -v "Illegal instruction\|core dumped\|Invalid ELF image for this architecture" | \
        grep -a -c -v "\-\-\-\-\-\-\-\-\-\-\-" || true)
      # print_output "[*] LOG_FILE: $lLOG_FILE - Lines: $lLINES_OF_LOG" "no_log"
      if ! [[ -s "${lLOG_FILE}" ]] || [[ "${lLINES_OF_LOG}" -eq 0 ]]; then
        # print_output "[*] Removing empty log file: $lLOG_FILE" "no_log"
        rm "${lLOG_FILE}" 2> /dev/null || true
        continue
      fi
      lBINARY_FROM_LOG=$(basename "${lLOG_FILE}")
      lBINARY_FROM_LOG=$(echo "${lBINARY_FROM_LOG}" | cut -d_ -f3 | sed 's/.txt$//')
      print_output "[+]""${NC}"" Emulated binary ""${GREEN}""${lBINARY_FROM_LOG}""${NC}"" generated output in ""${GREEN}""${lLOG_FILE}""${NC}""." "" "${lLOG_FILE}"
    done
  fi
  # if we created a backup for emulation - lets delete it now
  if [[ -d "${LOG_PATH_MODULE}/firmware" ]]; then
    print_output "[*] Remove firmware copy from emulation directory." "no_log"
    rm -r "${LOG_PATH_MODULE}"/firmware || true
  fi
}

creating_dev_area() {
  local lR_PATH="${1:-}"
  if ! [[ -d "${lR_PATH}" ]]; then
    print_output "[-] No lR_PATH found ..."
    return
  fi

  print_output "[*] Creating dev area for user mode emulation"

  if ! [[ -e "${lR_PATH}""/dev/console" ]] ; then
    print_output "[*] Creating /dev/console"
    mknod -m 622 "${lR_PATH}""/dev/console" c 5 1 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/null" ]] ; then
    print_output "[*] Creating /dev/null"
    mknod -m 666 "${lR_PATH}""/dev/null" c 1 3 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/zero" ]] ; then
    print_output "[*] Creating /dev/zero"
    mknod -m 666 "${lR_PATH}""/dev/zero" c 1 5 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/ptmx" ]] ; then
    print_output "[*] Creating /dev/ptmx"
    mknod -m 666 "${lR_PATH}""/dev/ptmx" c 5 2 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/tty" ]] ; then
    print_output "[*] Creating /dev/tty"
    mknod -m 666 "${lR_PATH}""/dev/tty" c 5 0 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/random" ]] ; then
    print_output "[*] Creating /dev/random"
    mknod -m 444 "${lR_PATH}""/dev/random" c 1 8 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/urandom" ]] ; then
    print_output "[*] Creating /dev/urandom"
    mknod -m 444 "${lR_PATH}""/dev/urandom" c 1 9 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/mem" ]] ; then
    print_output "[*] Creating /dev/mem"
    mknod -m 660 "${lR_PATH}"/dev/mem c 1 1 2> /dev/null || true
  fi
  if ! [[ -e "${lR_PATH}""/dev/kmem" ]] ; then
    print_output "[*] Creating /dev/kmem"
    mknod -m 640 "${lR_PATH}"/dev/kmem c 1 2 2> /dev/null || true
  fi
  if ! [[ -e "${lR_PATH}""/dev/armem" ]] ; then
    print_output "[*] Creating /dev/armem"
    mknod -m 666 "${lR_PATH}"/dev/armem c 1 13 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/tty0" ]] ; then
    print_output "[*] Creating /dev/tty0"
    mknod -m 622 "${lR_PATH}"/dev/tty0 c 4 0 2> /dev/null || true
  fi
  if ! [[ -e "${lR_PATH}""/dev/ttyS0" ]] ; then
    print_output "[*] Creating /dev/ttyS0 - ttyS3"
    mknod -m 660 "${lR_PATH}"/dev/ttyS0 c 4 64 2> /dev/null || true
    mknod -m 660 "${lR_PATH}"/dev/ttyS1 c 4 65 2> /dev/null || true
    mknod -m 660 "${lR_PATH}"/dev/ttyS2 c 4 66 2> /dev/null || true
    mknod -m 660 "${lR_PATH}"/dev/ttyS3 c 4 67 2> /dev/null || true
  fi

  if ! [[ -e "${lR_PATH}""/dev/adsl0" ]] ; then
    print_output "[*] Creating /dev/adsl0"
    mknod -m 644 "${lR_PATH}"/dev/adsl0 c 100 0 2> /dev/null || true
  fi
  if ! [[ -e "${lR_PATH}""/dev/ppp" ]] ; then
    print_output "[*] Creating /dev/ppp"
    mknod -m 644 "${lR_PATH}"/dev/ppp c 108 0 2> /dev/null || true
  fi
  if ! [[ -e "${lR_PATH}""/dev/hidraw0" ]] ; then
    print_output "[*] Creating /dev/hidraw0"
    mknod -m 666 "${lR_PATH}"/dev/hidraw0 c 251 0 2> /dev/null || true
  fi

  if ! [[ -d "${lR_PATH}"/dev/mtd ]]; then
    print_output "[*] Creating and populating /dev/mtd"
    mkdir -p "${lR_PATH}"/dev/mtd 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/0 c 90 0 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/1 c 90 2 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/2 c 90 4 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/3 c 90 6 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/4 c 90 8 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/5 c 90 10 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/6 c 90 12 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/7 c 90 14 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/8 c 90 16 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/9 c 90 18 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtd/10 c 90 20 2> /dev/null || true
  fi

  mknod -m 644 "${lR_PATH}"/dev/mtd0 c 90 0 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr0 c 90 1 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd1 c 90 2 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr1 c 90 3 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd2 c 90 4 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr2 c 90 5 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd3 c 90 6 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr3 c 90 7 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd4 c 90 8 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr4 c 90 9 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd5 c 90 10 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr5 c 90 11 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd6 c 90 12 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr6 c 90 13 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd7 c 90 14 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr7 c 90 15 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd8 c 90 16 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr8 c 90 17 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd9 c 90 18 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr9 c 90 19 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtd10 c 90 20 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdr10 c 90 21 2> /dev/null || true

  if ! [[ -d "${lR_PATH}"/dev/mtdblock ]]; then
    print_output "[*] Creating and populating /dev/mtdblock"
    mkdir -p "${lR_PATH}"/dev/mtdblock 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/0 b 31 0 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/1 b 31 1 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/2 b 31 2 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/3 b 31 3 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/4 b 31 4 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/5 b 31 5 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/6 b 31 6 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/7 b 31 7 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/8 b 31 8 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/9 b 31 9 2> /dev/null || true
    mknod -m 644 "${lR_PATH}"/dev/mtdblock/10 b 31 10 2> /dev/null || true
  fi

  mknod -m 644 "${lR_PATH}"/dev/mtdblock0 b 31 0 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock1 b 31 1 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock2 b 31 2 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock3 b 31 3 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock4 b 31 4 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock5 b 31 5 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock6 b 31 6 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock7 b 31 7 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock8 b 31 8 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock9 b 31 9 2> /dev/null || true
  mknod -m 644 "${lR_PATH}"/dev/mtdblock10 b 31 10 2> /dev/null || true

  if ! [[ -d "${lR_PATH}"/dev/tts ]]; then
    print_output "[*] Creating and populating /dev/tts"
    mkdir -p "${lR_PATH}"/dev/tts 2> /dev/null || true
    mknod -m 660 "${lR_PATH}"/dev/tts/0 c 4 64 2> /dev/null || true
    mknod -m 660 "${lR_PATH}"/dev/tts/1 c 4 65 2> /dev/null || true
    mknod -m 660 "${lR_PATH}"/dev/tts/2 c 4 66 2> /dev/null || true
    mknod -m 660 "${lR_PATH}"/dev/tts/3 c 4 67 2> /dev/null || true
  fi

  chown -v root:tty "${lR_PATH}""/dev/"{console,ptmx,tty} > /dev/null 2>&1 || true
}


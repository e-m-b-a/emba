#!/bin/bash -p

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
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Emulates executables from the firmware with qemu to get version information.
#               Currently this is an experimental module and needs to be activated separately via the -E switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

S115_usermode_emulator() {
  local NEG_LOG=0

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
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      return
    fi

    local EMULATOR="NA"
    local BIN_EMU_ARR=()
    local BIN_EMU_TMP=()
    local WAIT_PIDS_S115=()
    local MAX_THREADS_S115=1
    local BINARY=""
    local BIN_BLACKLIST=()
    export MISSING_AREAS=()
    export ROOT_CNT=0

    print_output "[*] This module creates a working copy of the firmware filesystem in the log directory ${LOG_DIR}.\\n"
    # get the local interface ip address for later verification
    # ensure that the emulator does not reconfigure the interface
    get_local_ip

    # some processes are running long and logging a lot
    # to protect the host we are going to kill them on a KILL_SIZE limit
    export KILL_SIZE="50M"

    # load blacklist of binaries that could cause troubles during emulation:
    readarray -t BIN_BLACKLIST < "${CONFIG_DIR}"/emulation_blacklist.cfg

    # as we modify the firmware area, we copy it to the log directory and do the modifications in this area
    copy_firmware

    detect_root_dir_helper "${EMULATION_PATH_BASE}"

    print_output "[*] Detected ${ORANGE}${#ROOT_PATH[@]}${NC} root directories:"

    kill_qemu_threader &
    export PID_killer="$!"
    disown "${PID_killer}" 2> /dev/null || true

    for R_PATH in "${ROOT_PATH[@]}" ; do
      print_ln
      NEG_LOG=1
      print_output "[*] Detected root path: ${ORANGE}${R_PATH}${NC}"
      if [[ -f "${HELP_DIR}"/fix_bins_lnk_emulation.sh ]] && [[ $(find "${R_PATH}" -type l | wc -l) -lt 10 ]]; then
        print_output "[*] No symlinks found in firmware ... Starting link fixing helper ..."
        "${HELP_DIR}"/fix_bins_lnk_emulation.sh "${R_PATH}"
      fi
      # MD5_DONE_INT is the array of all MD5 checksums for all root paths -> this is needed to ensure that we do not test bins twice
      local MD5_DONE_INT=()
      local BIN_CNT=0
      ((ROOT_CNT=ROOT_CNT+1))
      print_output "[*] Running emulation processes in ${ORANGE}${R_PATH}${NC} root path (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})."

      local DIR=""
      DIR=$(pwd)
      mapfile -t BIN_EMU_TMP < <(cd "${R_PATH}" && find . -xdev -ignore_readdir_race -type f ! \( -name "*.ko" -o -name "*.so" \) -print0|xargs -r -0 -P 16 -I % sh -c 'file % 2>/dev/null | grep "ELF.*executable\|ELF.*shared\ object" | grep -v "version\ .\ (FreeBSD)" | cut -d: -f1 2>/dev/null' && cd "${DIR}" || exit)
      # we re-create the BIN_EMU_ARR array with all unique binaries for every root directory
      # as we have all tested MD5s in MD5_DONE_INT (for all root dirs) we test every bin only once
      BIN_EMU_ARR=()

      print_output "[*] Create unique binary array for ${ORANGE}${R_PATH}${NC} root path (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})."

      for BINARY in "${BIN_EMU_TMP[@]}"; do
        # we emulate every binary only once. So calculate the checksum and store it for checking
        local BIN_MD5_=""
        BIN_MD5_=$(md5sum "${R_PATH}"/"${BINARY}" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_INT[*]} " =~ ${BIN_MD5_} ]]; then
          BIN_EMU_ARR+=( "${BINARY}" )
          MD5_DONE_INT+=( "${BIN_MD5_}" )
        fi
      done

      print_output "[*] Testing ${ORANGE}${#BIN_EMU_ARR[@]}${NC} unique executables in root dirctory: ${ORANGE}${R_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})."

      for BIN_ in "${BIN_EMU_ARR[@]}" ; do
        ((BIN_CNT=BIN_CNT+1))
        FULL_BIN_PATH="${R_PATH}"/"${BIN_}"

        local BIN_EMU_NAME_=""
        BIN_EMU_NAME_=$(basename "${FULL_BIN_PATH}")

        local THOLD=0
        THOLD=$(( 25*"${ROOT_CNT}" ))
        # if we have already a log file with a lot of content we assume this binary was already emulated correct
        if [[ $(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "${LOG_DIR}"/s115_usermode_emulator/qemu_init_"${BIN_EMU_NAME_}".txt 2>/dev/null | grep -c -v -E "\[\*\]\ " || true) -gt "${THOLD}" ]]; then
          print_output "[!] BIN ${BIN_EMU_NAME_} was already emulated ... skipping"
          continue
        fi

        if echo "${BIN_BLACKLIST[@]}" | grep -q -F -w "$(basename "${FULL_BIN_PATH}")"; then
          print_output "[*] Binary ${ORANGE}${BIN_}${NC} (${ORANGE}${BIN_CNT}/${#BIN_EMU_ARR[@]}${NC}) not emulated - blacklist triggered"
          continue
        else
          if [[ "${THREADED}" -eq 1 ]]; then
            # we adjust the max threads regularly. S115 respects the consumption of S09 and adjusts the threads
            MAX_THREADS_S115=$((5*"$(grep -c ^processor /proc/cpuinfo || true)"))
            if [[ $(grep -i -c S09_ "${LOG_DIR}"/"${MAIN_LOG_FILE}" || true) -eq 1 ]]; then
              # if only one result for S09_ is found in emba.log means the S09 module is started and currently running
              MAX_THREADS_S115=$((3*"$(grep -c ^processor /proc/cpuinfo || true)"))
            fi
          fi
          if [[ "${BIN_}" != './qemu-'*'-static' ]]; then
            if ( file -b "${FULL_BIN_PATH}" | grep -q "version\ .\ (FreeBSD)" ) ; then
              # https://superuser.com/questions/1404806/running-a-freebsd-binary-on-linux-using-qemu-user
              print_output "[-] No working emulator found for FreeBSD binary ${ORANGE}${BIN_}${NC}."
              EMULATOR="NA"
              continue
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "x86-64" ) ; then
              EMULATOR="qemu-x86_64-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "Intel 80386" ) ; then
              EMULATOR="qemu-i386-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "32-bit LSB.*ARM" ) ; then
              EMULATOR="qemu-arm-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "32-bit MSB.*ARM" ) ; then
              EMULATOR="qemu-armeb-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "64-bit LSB.*ARM aarch64" ) ; then
              EMULATOR="qemu-aarch64-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "64-bit MSB.*ARM aarch64" ) ; then
              EMULATOR="qemu-aarch64_be-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "32-bit LSB.*MIPS" ) ; then
              EMULATOR="qemu-mipsel-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "ELF 32-bit MSB executable, MIPS, N32 MIPS64 rel2 version 1" ) ; then
              EMULATOR="qemu-mipsn32-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "32-bit MSB.*MIPS" ) ; then
              EMULATOR="qemu-mips-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "64-bit LSB.*MIPS" ) ; then
              EMULATOR="qemu-mips64el-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "64-bit MSB.*MIPS" ) ; then
              EMULATOR="qemu-mips64-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "32-bit MSB.*PowerPC" ) ; then
              EMULATOR="qemu-ppc-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "ELF 32-bit LSB executable, Altera Nios II" ) ; then
              EMULATOR="qemu-nios2-static"
            elif ( file -b "${FULL_BIN_PATH}" | grep -q "ELF 32-bit LSB shared object, QUALCOMM DSP6" ) ; then
              EMULATOR="qemu-hexagon-static"
            else
              print_output "[-] No working emulator found for ${BIN_}"
              EMULATOR="NA"
              continue
            fi

            if [[ "${EMULATOR}" != "NA" ]]; then
              prepare_emulator "${R_PATH}" "${EMULATOR}"
              if [[ "${THREADED}" -eq 1 ]]; then
                emulate_binary "${EMULATOR}" "${R_PATH}" "${BIN_}" &
                local TMP_PID="$!"
                store_kill_pids "${TMP_PID}"
                write_pid_log "${FUNCNAME[0]} - emulate_binary - ${BIN_} - ${TMP_PID}"
                WAIT_PIDS_S115+=( "${TMP_PID}" )
                max_pids_protection "${MAX_THREADS_S115}" "${WAIT_PIDS_S115[@]}"
              else
                emulate_binary "${EMULATOR}" "${R_PATH}" "${BIN_}"
              fi
            fi
          fi
          running_jobs
        fi
      done
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S115[@]}"

    s115_cleanup "${EMULATOR}"
    running_jobs
    print_filesystem_fixes
    recover_local_ip "${IP_ETH0}"

  else
    print_ln
    print_output "[!] Automated emulation is disabled."
    print_output "[!] Enable it with the ${ORANGE}-E${MAGENTA} switch.${NC}"
  fi

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

copy_firmware() {
  local FREE_SPACE=""
  local NEEDED_SPACE=0

  if [[ -d "${FIRMWARE_PATH_BAK}" ]]; then
    export EMULATION_PATH_BASE="${FIRMWARE_PATH}"
  else
    export EMULATION_PATH_BASE="${LOG_DIR}"/firmware
  fi

  # we create a backup copy for user mode emulation only if we have enough disk space.
  # If there is not enough disk space we use the original firmware directory
  FREE_SPACE="$(df --output=avail "${LOG_DIR}" | awk 'NR==2')"
  NEEDED_SPACE="$(( "$(du --max-depth=0 "${EMULATION_PATH_BASE}" | awk '{print $1}')" + 10000 ))"

  if [[ "${FREE_SPACE}" -gt "${NEEDED_SPACE}" ]]; then
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
  local R_PATH="${1:-}"
  local EMULATOR="${2:-}"

  if [[ ! -e "${R_PATH}""/""${EMULATOR}" ]]; then

    sub_module_title "Preparation phase"

    print_output "[*] Preparing the environment for usermode emulation"
    if ! command -v "${EMULATOR}" > /dev/null ; then
      print_ln "no_log"
      print_output "[!] Is the qemu package installed?"
      print_output "$(indent "We can't find it!")"
      print_output "$(indent "$(red "Terminating EMBA now.\\n")")"
      exit 1
    else
      cp "$(command -v "${EMULATOR}")" "${R_PATH}" || (print_output "[-] Issues in copy emulator process for emulator ${EMULATOR}" && return)
    fi

    if ! [[ -d "${R_PATH}""/proc" ]] ; then
      mkdir "${R_PATH}""/proc" 2> /dev/null || true
    fi

    if ! [[ -d "${R_PATH}""/sys" ]] ; then
      mkdir "${R_PATH}""/sys" 2> /dev/null || true
    fi

    if ! [[ -d "${R_PATH}""/run" ]] ; then
      mkdir "${R_PATH}""/run" 2> /dev/null || true
    fi

    if ! [[ -d "${R_PATH}""/dev/" ]] ; then
      mkdir "${R_PATH}""/dev/" 2> /dev/null || true
    fi

    if ! mount | grep "${R_PATH}"/proc > /dev/null ; then
      mount proc "${R_PATH}""/proc" -t proc 2> /dev/null || true
    fi
    if ! mount | grep "${R_PATH}/run" > /dev/null ; then
      mount -o bind /run "${R_PATH}""/run" 2> /dev/null || true
    fi
    if ! mount | grep "${R_PATH}/sys" > /dev/null ; then
      mount -o bind /sys "${R_PATH}""/sys" 2> /dev/null || true
    fi

    creating_dev_area "${R_PATH}"

    print_ln
    print_output "[*] Currently mounted areas:"
    print_output "$(indent "$(mount | grep "${R_PATH}" 2> /dev/null || true)")""\\n"

    print_output "[*] Final fixes of the root filesytem in a chroot environment"
    cp "${HELP_DIR}"/fixImage_user_mode_emulation.sh "${R_PATH}"
    chmod +x "${R_PATH}"/fixImage_user_mode_emulation.sh
    cp "$(command -v busybox)" "${R_PATH}"
    chmod +x "${R_PATH}"/busybox
    if [[ "${CHROOT}" == "jchroot" ]]; then
      "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- /busybox ash /fixImage_user_mode_emulation.sh | tee -a "${LOG_PATH_MODULE}"/chroot_fixes.txt || print_error "[-] Something weird going wrong in jchroot filesystem fixing for ${R_PATH}"
    else
      "${CHROOT}" "${OPTS[@]}" "${R_PATH}" /busybox ash /fixImage_user_mode_emulation.sh | tee -a "${LOG_PATH_MODULE}"/chroot_fixes.txt || print_error "[-] Something weird going wrong in chroot filesystem fixing for ${R_PATH}"
    fi
    rm "${R_PATH}"/fixImage_user_mode_emulation.sh || true
    rm "${R_PATH}"/busybox || true
    print_bar
  fi
}

# Iterates through possible qemu CPU configs
# this is a jumper function for further processing and at the end running
# emulation with the CPU config in strace mode
run_init_test() {
  local FULL_BIN_PATH="${1:-}"
  local BIN_EMU_NAME_=""
  BIN_EMU_NAME_=$(basename "${FULL_BIN_PATH}")
  local LOG_FILE_INIT="${LOG_PATH_MODULE}""/qemu_init_""${BIN_EMU_NAME_}"".txt"
  local CPU_CONFIGS=()
  local CPU_CONFIG_=""

  write_log "\\n-----------------------------------------------------------------\\n" "${LOG_FILE_INIT}"

  # get the most used cpu configuration for the initial check:
  if [[ -f "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" ]]; then
    CPU_CONFIG_=$(grep -a CPU_CONFIG "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" | cut -d\; -f2 | uniq -c | sort -nr | head -1 | awk '{print $2}' || true)
  fi

  print_output "[*] Initial CPU detection process of binary ${ORANGE}${BIN_EMU_NAME_}${NC} with CPU configuration ${ORANGE}${CPU_CONFIG_}${NC}." "${LOG_FILE_INIT}" "${LOG_FILE_INIT}"
  write_log "[*] Emulator used: ${ORANGE}${EMULATOR}${NC}" "${LOG_FILE_INIT}"
  write_log "[*] Using root directory: ${ORANGE}${R_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})" "${LOG_FILE_INIT}"
  write_log "" "${LOG_FILE_INIT}"

  if [[ "${CHROOT}" == "jchroot" ]]; then
    timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" --strace "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_chroot_check_""${BIN_EMU_NAME_}"".txt" 2>&1 || true
    PID="$!"
    disown "${PID}" 2> /dev/null || true
    if [[ -f "${LOG_PATH_MODULE}""/qemu_chroot_check_""${BIN_EMU_NAME_}"".txt" ]] && grep -q "unable to create temporary directory for pivot root: Permission denied" "${LOG_PATH_MODULE}""/qemu_chroot_check_""${BIN_EMU_NAME_}"".txt"; then
      print_output "[*] jchroot issues identified - ${ORANGE}switching to chroot${NC}" "no_log"
      setup_chroot
    fi
    if [[ -f "${LOG_PATH_MODULE}""/qemu_chroot_check_""${BIN_EMU_NAME_}"".txt" ]]; then
      rm "${LOG_PATH_MODULE}""/qemu_chroot_check_""${BIN_EMU_NAME_}"".txt" || true
    fi
  fi
  run_init_qemu "${CPU_CONFIG_}" "${BIN_EMU_NAME_}" "${LOG_FILE_INIT}"

  if [[ ! -f "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" || $(grep -a -c "Illegal instruction\|cpu_init.*failed" "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" 2> /dev/null) -gt 0 || $(wc -l "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" | awk '{print $1}') -lt 6 ]]; then

    write_log "[-] Emulation process of binary ${ORANGE}${BIN_EMU_NAME_}${NC} with CPU configuration ${ORANGE}${CPU_CONFIG_}${NC} failed" "${LOG_FILE_INIT}"

    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      mapfile -t CPU_CONFIGS < <("${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" -cpu help | grep -v alias | awk '{print $2}' | tr -d "'" || true)
    else
      mapfile -t CPU_CONFIGS < <("${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${EMULATOR}" -cpu help | grep -v alias | awk '{print $2}' | tr -d "'" || true)
    fi

    for CPU_CONFIG_ in "${CPU_CONFIGS[@]}"; do
      if [[ -f "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" ]]; then
        rm "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" || true
      fi

      run_init_qemu "${CPU_CONFIG_}" "${BIN_EMU_NAME_}" "${LOG_FILE_INIT}"

      if [[ -z "${CPU_CONFIG_}" ]]; then
        CPU_CONFIG_="NONE"
      fi

      if [[ ! -f "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" || $(grep -a -c "Illegal instruction\|cpu_init.*failed" "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" 2> /dev/null) -gt 0 || $(wc -l "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" | awk '{print $1}') -lt 6 ]]; then
        write_log "[-] Emulation process of binary ${ORANGE}${BIN_EMU_NAME_}${NC} with CPU configuration ${ORANGE}${CPU_CONFIG_}${NC} failed" "${LOG_FILE_INIT}"
        continue
      fi

      write_log "" "${LOG_FILE_INIT}"
      write_log "[+] CPU configuration used for ${ORANGE}${BIN_EMU_NAME_}${GREEN}: ${ORANGE}${CPU_CONFIG_}${GREEN}" "${LOG_FILE_INIT}"
      write_log "CPU_CONFIG_det\;${CPU_CONFIG_}" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"
      write_log "CPU_CONFIG_det\;${CPU_CONFIG_}" "${LOG_FILE_INIT}"
      break

    done
  else
    [[ -z "${CPU_CONFIG_}" ]] && CPU_CONFIG_="NONE"

    write_log "[+] CPU configuration used for ${ORANGE}${BIN_EMU_NAME_}${GREEN}: ${ORANGE}${CPU_CONFIG_}${GREEN}" "${LOG_FILE_INIT}"
    write_log "CPU_CONFIG_det\;${CPU_CONFIG_}" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"
    write_log "CPU_CONFIG_det\;${CPU_CONFIG_}" "${LOG_FILE_INIT}"
  fi

  # fallback solution - we use the most working configuration:
  if [[ -f "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" ]] && ! grep -q "CPU_CONFIG_det" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"; then
    CPU_CONFIG_=$(grep -a CPU_CONFIG "${LOG_PATH_MODULE}""/qemu_init_cpu.txt" | cut -d\; -f2 | uniq -c | sort -nr | head -1 | awk '{print $2}' || true)
    write_log "[+] CPU configuration used for ${ORANGE}${BIN_EMU_NAME_}${GREEN}: ${ORANGE}${CPU_CONFIG_}${GREEN}" "${LOG_FILE_INIT}"
    write_log "CPU_CONFIG_det\;${CPU_CONFIG_}" "${LOG_PATH_MODULE}""/qemu_init_cpu.txt"
    write_log "CPU_CONFIG_det\;${CPU_CONFIG_}" "${LOG_FILE_INIT}"
    write_log "[*] Fallback to most found CPU configuration" "${LOG_FILE_INIT}"
  fi
  sed -i 's/.REF.*//' "${LOG_FILE_INIT}"
  write_log "\\n-----------------------------------------------------------------\\n" "${LOG_FILE_INIT}"
}

# jump function for run_init_qemu_runner -> runs emulation process with stracer
# The goal is to find a working CPU configuration for qemu
run_init_qemu() {
  local CPU_CONFIG_="${1:-}"
  local BIN_EMU_NAME_="${2:-}"
  local LOG_FILE_INIT="${3:-}"

  # Enable the following echo output for debugging
  # echo "BIN: $BIN_" | tee -a "${LOG_FILE_INIT}"
  # echo "EMULATOR: $EMULATOR" | tee -a "${LOG_FILE_INIT}"
  # echo "R_PATH: $R_PATH" | tee -a "${LOG_FILE_INIT}"
  # echo "CPU_CONFIG: $CPU_CONFIG_" | tee -a "${LOG_FILE_INIT}"

  [[ "${STRICT_MODE}" -eq 1 ]] && set +e
  run_init_qemu_runner "${CPU_CONFIG_}" "${BIN_EMU_NAME_}" "${LOG_FILE_INIT}" &
  PID=$!
  write_pid_log "${FUNCNAME[0]} - runner - ${BIN_} - ${PID}"
  [[ "${STRICT_MODE}" -eq 1 ]] && set -e
  disown "${PID}" 2> /dev/null || true

  # wait a bit and then kill it
  sleep 1
  kill -9 "${PID}" 2> /dev/null || true
  if [[ -f "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" ]]; then
    cat "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" >> "${LOG_FILE_INIT}" || true
  fi

}

# runs emulation process with stracer - for CPU config detection
run_init_qemu_runner() {
  local CPU_CONFIG_="${1:-}"
  local BIN_EMU_NAME_="${2:-}"
  local LOG_FILE_INIT="${3:-}"

  if [[ -z "${CPU_CONFIG_}" || "${CPU_CONFIG_}" == "NONE" ]]; then
    write_log "[*] Trying to emulate binary ${ORANGE}${BIN_}${NC} with cpu config ${ORANGE}NONE${NC}" "${LOG_FILE_INIT}"
    write_log "" "${LOG_FILE_INIT}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" --strace "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" 2>&1 || true
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${EMULATOR}" --strace "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" 2>&1 || true
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    fi
  else
    write_log "[*] Trying to emulate binary ${ORANGE}${BIN_}${NC} with cpu config ${ORANGE}${CPU_CONFIG_}${NC}" "${LOG_FILE_INIT}"
    write_log "" "${LOG_FILE_INIT}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" --strace -cpu "${CPU_CONFIG_}" "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" 2>&1 || true
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${EMULATOR}" --strace -cpu "${CPU_CONFIG_}" "${BIN_}" >> "${LOG_PATH_MODULE}""/qemu_initx_""${BIN_EMU_NAME_}"".txt" 2>&1 || true
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    fi
  fi
}

# runs emulation process with stracer for detection of missing filesystem areas
# the goal is to search these missing areas within the extracted firmware
# sometimes we can find them and copy to the right area
emulate_strace_run() {
  local CPU_CONFIG_="${1:-}"
  local BIN_EMU_NAME="${2:-}"
  local MISSING_AREAS_TMP=()
  local LOG_FILE_STRACER="${LOG_PATH_MODULE}""/stracer_""${BIN_EMU_NAME}"".txt"
  local FILENAME_MISSING=""
  local PATH_MISSING=""
  local FILENAME_FOUND=""

  write_log "\\n-----------------------------------------------------------------\\n" "${LOG_FILE_STRACER}"

  print_output "[*] Initial strace run with ${ORANGE}${CHROOT}${NC} on the command ${ORANGE}${BIN_}${NC} to identify missing areas" "${LOG_FILE_STRACER}" "${LOG_FILE_STRACER}"
  write_log "[*] Emulating binary name: ${ORANGE}${BIN_EMU_NAME}${NC} in ${ORANGE}strace${NC} mode to identify missing areas (with ${ORANGE}${CHROOT}${NC})" "${LOG_FILE_STRACER}"
  write_log "[*] Emulator used: ${ORANGE}${EMULATOR}${NC}" "${LOG_FILE_STRACER}"
  write_log "[*] Chroot environment used: ${ORANGE}${CHROOT}${NC}" "${LOG_FILE_STRACER}"
  write_log "[*] Using root directory: ${ORANGE}${R_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})" "${LOG_FILE_STRACER}"
  write_log "[*] Using CPU config: ${ORANGE}${CPU_CONFIG_}${NC}" "${LOG_FILE_STRACER}"
  write_log "" "${LOG_FILE_STRACER}"

  # currently we only look for file errors (errno=2) and try to fix this
  [[ "${STRICT_MODE}" -eq 1 ]] && set +e
  if [[ -z "${CPU_CONFIG_}" || "${CPU_CONFIG_}" == *"NONE"* ]]; then
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" --strace "${BIN_}" >> "${LOG_FILE_STRACER}" 2>&1 &
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${EMULATOR}" --strace "${BIN_}" >> "${LOG_FILE_STRACER}" 2>&1 &
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    fi
  else
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" -cpu "${CPU_CONFIG_}" --strace "${BIN_}" >> "${LOG_FILE_STRACER}" 2>&1 &
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    else
      timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${EMULATOR}" -cpu "${CPU_CONFIG_}" --strace "${BIN_}" >> "${LOG_FILE_STRACER}" 2>&1 &
      PID="$!"
      disown "${PID}" 2> /dev/null || true
    fi
  fi
  write_pid_log "${FUNCNAME[0]} - ${CHROOT} - ${BIN_} - ${PID}"
  [[ "${STRICT_MODE}" -eq 1 ]] && set -e

  # wait a second and then kill it
  sleep 1
  kill -9 "${PID}" 2> /dev/null || true

  # extract missing files, exclude *.so files:
  write_log "" "${LOG_FILE_STRACER}"
  write_log "[*] Identification of missing filesytem areas." "${LOG_FILE_STRACER}"

  mapfile -t MISSING_AREAS < <(grep -a "open.*errno=2\ " "${LOG_FILE_STRACER}" 2>&1 | cut -d\" -f2 2>&1 | sort -u || true)
  mapfile -t MISSING_AREAS_TMP < <(grep -a "^qemu.*: Could not open" "${LOG_FILE_STRACER}" | cut -d\' -f2 2>&1 | sort -u || true)
  MISSING_AREAS+=("${MISSING_AREAS_TMP[@]}" )

  if [[ "${#MISSING_AREAS[@]}" -gt 0 ]]; then
    for MISSING_AREA in "${MISSING_AREAS[@]}"; do
      if [[ "${MISSING_AREA}" != *"/proc/"* && "${MISSING_AREA}" != *"/sys/"* && "${MISSING_AREA}" != *"/dev/"* ]]; then
        write_log "[*] Found missing area: ${ORANGE}${MISSING_AREA}${NC}" "${LOG_FILE_STRACER}"

        FILENAME_MISSING=$(basename "${MISSING_AREA}")
        write_log "[*] Trying to identify this missing file: ${ORANGE}${FILENAME_MISSING}${NC}" "${LOG_FILE_STRACER}"
        PATH_MISSING=$(dirname "${MISSING_AREA}")

        FILENAME_FOUND=$(find "${EMULATION_PATH_BASE}" -xdev -ignore_readdir_race -name "${FILENAME_MISSING}" 2>/dev/null | sort -u | head -1 || true)
        if [[ "${FILENAME_FOUND}" == *"/proc/"* || "${FILENAME_FOUND}" == *"/sys/"* || "${FILENAME_FOUND}" == *"/dev/"* ]]; then
          continue
        fi
        if [[ -n "${FILENAME_FOUND}" ]]; then
          write_log "[*] Possible matching file found: ${ORANGE}${FILENAME_FOUND}${NC}" "${LOG_FILE_STRACER}"
        fi

        if [[ ! -d "${R_PATH}""${PATH_MISSING}" ]]; then
          write_log "[*] Creating directory ${ORANGE}${R_PATH}${PATH_MISSING}${NC}" "${LOG_FILE_STRACER}"
          mkdir -p "${R_PATH}""${PATH_MISSING}" 2> /dev/null || true
          # continue
        fi
        if [[ -n "${FILENAME_FOUND}" ]]; then
          write_log "[*] Copy file ${ORANGE}${FILENAME_FOUND}${NC} to ${ORANGE}${R_PATH}${PATH_MISSING}/${NC}" "${LOG_FILE_STRACER}"
          local OUTPUT=""
          OUTPUT=$(file -b "${FILENAME_FOUND}")
          if [[ "${OUTPUT}" != *"(named pipe)" ]];then
            cp -L "${FILENAME_FOUND}" "${R_PATH}""${PATH_MISSING}" 2> /dev/null || true
          fi
          continue
        else
        #  # disabled this for now - have to rethink this feature
        #  # This can only be used on non library and non elf files. How can we identify them without knowing them?
        #  write_log "[*] Creating empty file $ORANGE$R_PATH$PATH_MISSING/$FILENAME_MISSING$NC" "${LOG_FILE_STRACER}"
        #  touch "${R_PATH}""${PATH_MISSING}"/"${FILENAME_MISSING}" 2> /dev/null
          write_log "[*] Missing file ${ORANGE}${R_PATH}${PATH_MISSING}/${FILENAME_MISSING}${NC}" "${LOG_FILE_STRACER}"
          continue
        fi
      fi
    done
  else
    write_log "[*] No missing areas found." "${LOG_FILE_STRACER}"
  fi

  if [[ -f "${LOG_FILE_STRACER}" ]]; then
    # remove the REF entries for printing the log file to the screen
    sed -i 's/.REF.*//' "${LOG_FILE_STRACER}"
    # print it to the screen - we already have the output in the right log file
    cat "${LOG_FILE_STRACER}" || true
    write_log "\\n-----------------------------------------------------------------\\n" "${LOG_FILE_STRACER}"
  fi
}

emulate_binary() {
  local EMULATOR="${1:-}"
  local R_PATH="${2:-}"
  local BIN_="${3:-}"

  FULL_BIN_PATH="${R_PATH}"/"${BIN_}"

  if ! [[ -f "${FULL_BIN_PATH}" ]]; then
    print_output "[-] ${ORANGE}${FULL_BIN_PATH}${NC} not found"
    return
  fi
  local EMULATION_PARAMS=()
  local PARAM=""

  BIN_EMU_NAME=$(basename "${FULL_BIN_PATH}")
  local LOG_FILE_BIN="${LOG_PATH_MODULE}""/qemu_tmp_""${BIN_EMU_NAME}"".txt"

  run_init_test "${FULL_BIN_PATH}"
  # now we should have CPU_CONFIG in log file from Binary

  local CPU_CONFIG_=""
  CPU_CONFIG_="$(grep -a "CPU_CONFIG_det" "${LOG_PATH_MODULE}""/qemu_init_""${BIN_EMU_NAME}"".txt" | cut -d\; -f2 | sort -u | head -1 || true)"

  write_log "\\n-----------------------------------------------------------------\\n" "${LOG_FILE_BIN}"
  write_log "[*] Emulating binary name: ${ORANGE}${BIN_EMU_NAME}${NC}" "${LOG_FILE_BIN}"
  write_log "[*] Emulator used: ${ORANGE}${EMULATOR}${NC}" "${LOG_FILE_BIN}"
  write_log "[*] Using root directory: ${ORANGE}${R_PATH}${NC} (${ORANGE}${ROOT_CNT}/${#ROOT_PATH[@]}${NC})" "${LOG_FILE_BIN}"
  write_log "[*] Using CPU config: ${ORANGE}${CPU_CONFIG_}${NC}" "${LOG_FILE_BIN}"
  # write_log "[*] Root path used: $ORANGE$R_PATH$NC" "${LOG_FILE_BIN}"
  write_log "[*] Emulating binary: ${ORANGE}${BIN_/\.}${NC}" "${LOG_FILE_BIN}"
  write_log "" "${LOG_FILE_BIN}"

  # lets assume we now have only ELF files. Sometimes the permissions of firmware updates are completely weird
  # we are going to give all ELF files exec permissions to execute it in the emulator
  if ! [[ -x "${FULL_BIN_PATH}" ]]; then
    write_log "[*] Change permissions +x to ${ORANGE}${FULL_BIN_PATH}${NC}." "${LOG_FILE_BIN}"
    chmod +x "${FULL_BIN_PATH}"
  fi
  emulate_strace_run "${CPU_CONFIG_}" "${BIN_EMU_NAME}"

  # emulate binary with different command line parameters:
  if [[ "${BIN_}" == *"bash"* ]]; then
    EMULATION_PARAMS=("--help" "--version")
  else
    EMULATION_PARAMS=("" "-v" "-V" "-h" "-help" "--help" "--version" "version")
  fi

  for PARAM in "${EMULATION_PARAMS[@]}"; do
    [[ -z "${PARAM}" ]] && PARAM="NONE"

    [[ "${STRICT_MODE}" -eq 1 ]] && set +e
    if [[ -z "${CPU_CONFIG_}" ]] || [[ "${CPU_CONFIG_}" == "NONE" ]]; then
      write_log "[*] Emulating binary ${ORANGE}${BIN_}${NC} with parameter ${ORANGE}${PARAM}${NC}" "${LOG_FILE_BIN}"
      if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" "${BIN_}" "${PARAM}" &>> "${LOG_FILE_BIN}" || true &
        PID="$!"
        disown "${PID}" 2> /dev/null || true
      else
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${EMULATOR}" "${BIN_}" "${PARAM}" &>> "${LOG_FILE_BIN}" || true &
        PID="$!"
        disown "${PID}" 2> /dev/null || true
      fi
    else
      write_log "[*] Emulating binary ${ORANGE}${BIN_}${NC} with parameter ${ORANGE}${PARAM}${NC} and cpu configuration ${ORANGE}${CPU_CONFIG_}${NC}" "${LOG_FILE_BIN}"
      if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${EMULATOR}" -cpu "${CPU_CONFIG_}" "${BIN_}" "${PARAM}" &>> "${LOG_FILE_BIN}" || true &
        PID="$!"
        disown "${PID}" 2> /dev/null || true
      else
        timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${R_PATH}" ./"${EMULATOR}" -cpu "${CPU_CONFIG_}" "${BIN_}" "${PARAM}" &>> "${LOG_FILE_BIN}" || true &
        PID="$!"
        disown "${PID}" 2> /dev/null || true
      fi
    fi
    write_pid_log "${FUNCNAME[0]} - ${CHROOT} qemu final run - ${BIN_} - ${PID}"
    [[ "${STRICT_MODE}" -eq 1 ]] && set -e
    check_disk_space_emu
  done

  # now we kill all older qemu-processes:
  # if we use the correct identifier $EMULATOR it will not work ...
  # This is very ugly and should only be used in docker environment!
  pkill -9 -O "${QRUNTIME}" -f .*qemu-.*-sta.* >/dev/null || true
  write_log "\\n-----------------------------------------------------------------\\n" "${LOG_FILE_BIN}"
  write_log "\\n\\nFor reproducing the EMBA user-mode emulation mechanism, the following commands could be used as starting point:" "${LOG_FILE_BIN}"
  write_log "\\n - Start EMBA docker container with the firmware directory as log directory:" "${LOG_FILE_BIN}"
  local lFW_PATH=""
  lFW_PATH=$(sort -u "${TMP_DIR}"/fw_name.log | head -1)
  write_log "      # ${ORANGE}EMBA=\".\" FIRMWARE=\"${lFW_PATH:-"/absolute/path/to/firmware"}\" LOG=\"/absolute/path/to/EMBA/log/directory\" docker-compose run emba${NC}" "${LOG_FILE_BIN}"
  write_log "\\n - Change your working directory to the root directory of your firmware:" "${LOG_FILE_BIN}"
  write_log "      # ${ORANGE}cd ${R_PATH}${NC}" "${LOG_FILE_BIN}"
  write_log "\\n - Copy the static compiled user-mode emulator to your current working directory" "${LOG_FILE_BIN}"
  write_log "      # ${ORANGE}cp \$(which ${EMULATOR}) .${NC}" "${LOG_FILE_BIN}"
  if [[ -z "${CPU_CONFIG_}" ]] || [[ "${CPU_CONFIG_}" == "NONE" ]]; then
    write_log "\\n - Start the emulation with the following command: " "${LOG_FILE_BIN}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . -- ./${EMULATOR} ${BIN_} <parameters like -v or --help>${NC}" "${LOG_FILE_BIN}"
    else
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . ./${EMULATOR} ${BIN_} <parameters like -v or --help>${NC}" "${LOG_FILE_BIN}"
    fi
  else
    write_log "\\n - Start the emulation with the following command: " "${LOG_FILE_BIN}"
    if [[ "${CHROOT}" == "jchroot" ]] || grep -q "jchroot" "${TMP_DIR}"/chroot_mode.tmp; then
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . -- ./${EMULATOR} -cpu ${CPU_CONFIG_} ${BIN_} <parameters like -v or --help>${NC}" "${LOG_FILE_BIN}"
    else
      write_log "      # ${ORANGE}${CHROOT} ${OPTS[*]} . ./${EMULATOR} -cpu ${CPU_CONFIG_} ${BIN_} <parameters like -v or --help>${NC}" "${LOG_FILE_BIN}"
    fi
  fi
  write_log "\\n${ORANGE}WARNING: EMBA is doing some more magic in the background. Probably it is not that easy, but give it a try.${NC}" "${LOG_FILE_BIN}"
}

check_disk_space_emu() {
  local CRITICAL_FILES=()
  local KILLER=""

  mapfile -t CRITICAL_FILES < <(find "${LOG_PATH_MODULE}"/ -xdev -type f -size +"${KILL_SIZE}" -print0|xargs -r -0 -P 16 -I % sh -c 'basename % 2>/dev/null| cut -d\. -f1 | cut -d_ -f2' || true)
  for KILLER in "${CRITICAL_FILES[@]}"; do
    if pgrep -f "${EMULATOR}.*${KILLER}" > /dev/null; then
      print_output "[!] Qemu processes are wasting disk space ... we try to kill it" "no_log"
      print_output "[*] Killing process ${ORANGE}${EMULATOR}.*${KILLER}.*${NC}" "no_log"
      pkill -f "${EMULATOR}.*${KILLER}.*" >/dev/null|| true
      # rm "${LOG_DIR}"/qemu_emulator/*"${KILLER}"*
    fi
  done
}

running_jobs() {
  local CJOBS=""

  # if no emulation at all was possible the $EMULATOR variable is not defined
  if [[ -n "${EMULATOR}" ]]; then
    CJOBS=$(pgrep -f -c -a "${EMULATOR}" || true)
    if [[ -n "${CJOBS}" ]] ; then
      print_ln "no_log"
      print_output "[*] Currently running emulation jobs: ${ORANGE}${CJOBS}${NC}" "no_log"
    else
      CJOBS="NA"
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
  local IP_TO_CHECK_="${1:-}"

  if ! ifconfig eth0 | grep -q "${IP_TO_CHECK_}"; then
    print_ln
    print_output "[!] Warning: The emulation process of S115 has reconfigured your network interface."
    print_output "[*] We try to recover the interface ${ORANGE}eth0${NC}with address ${ORANGE}${IP_TO_CHECK_}${NC}"
    ifconfig eth0 "${IP_TO_CHECK_}" up
  fi
}

print_filesystem_fixes() {
  local MISSING_FILE=""

  # MISSING_AREAS array from emulate_strace_run
  if [[ "${#MISSING_AREAS[@]}" -ne 0 ]]; then
    sub_module_title "Filesystem fixes"
    print_output "[*] EMBA has auto-generated the files during runtime."
    print_output "[*] For persistence you could generate it manually in your filesystem.\\n"
    for MISSING_FILE in "${MISSING_AREAS[@]}"; do
      print_output "[*] Missing file: ${ORANGE}${MISSING_FILE}${NC}"
    done
  fi
}

s115_cleanup() {
  print_ln
  sub_module_title "Cleanup phase"
  local EMULATOR="${1:-}"
  local CHECK_MOUNTS=()
  local MOUNT=""
  local CJOBS_=""
  local LOG_FILES=()
  local BIN=""

  # rm "${LOG_PATH_MODULE}""/stracer_*.txt" 2>/dev/null || true

  # if no emulation at all was possible the $EMULATOR variable is not defined
  if [[ -n "${EMULATOR}" ]]; then
    print_output "[*] Terminating qemu processes - check it with ps"
    pkill -9 -f .*qemu-.*-sta.* >/dev/null || true
  fi

  CJOBS_=$(pgrep -f qemu- || true)
  if [[ -n "${CJOBS_}" ]] ; then
    print_output "[*] More emulation jobs are running ... we kill it with fire\\n"
    pkill -9 -f .*"${EMULATOR}".* >/dev/null || true
  fi
  kill -9 "${PID_killer}" >/dev/null || true

  print_output "[*] Cleaning the emulation environment\\n"
  find "${EMULATION_PATH_BASE}" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null || true
  find "${EMULATION_PATH_BASE}" -xdev -iname "*.core" -exec rm {} \; 2>/dev/null || true

  print_ln
  print_output "[*] Umounting proc, sys and run"
  mapfile -t CHECK_MOUNTS < <(mount | grep "${EMULATION_PATH_BASE}" || true)
  if [[ -v CHECK_MOUNTS[@] ]]; then
    for MOUNT in "${CHECK_MOUNTS[@]}"; do
      print_output "[*] Unmounting ${MOUNT}"
      MOUNT=$(echo "${MOUNT}" | cut -d\  -f3)
      umount -l "${MOUNT}" || true
    done
  fi

  mapfile -t LOG_FILES < <(find "${LOG_PATH_MODULE}""/" -xdev -type f -name "qemu_tmp*" 2>/dev/null)
  local ILLEGAL_INSTRUCTIONS_CNT=0
  # shellcheck disable=SC2126
  ILLEGAL_INSTRUCTIONS_CNT=$(grep -l "Illegal instruction" "${LOG_PATH_MODULE}""/"qemu_tmp* | wc -l || true)
  if [[ "${ILLEGAL_INSTRUCTIONS_CNT}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${ILLEGAL_INSTRUCTIONS_CNT}${NC}binaries not emulated - Illegal instructions"
  fi
  if [[ "${#LOG_FILES[@]}" -gt 0 ]] ; then
    sub_module_title "Reporting phase"
    for LOG_FILE_ in "${LOG_FILES[@]}" ; do
      local LINES_OF_LOG=0
      LINES_OF_LOG=$(grep -a -v -e "^[[:space:]]*$" "${LOG_FILE_}" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | \
        grep -a -v "\[\*\] " | grep -a -v "Illegal instruction\|core dumped\|Invalid ELF image for this architecture" | \
        grep -a -c -v "\-\-\-\-\-\-\-\-\-\-\-" || true)
      # print_output "[*] LOG_FILE: $LOG_FILE_ - Lines: $LINES_OF_LOG" "no_log"
      if ! [[ -s "${LOG_FILE_}" ]] || [[ "${LINES_OF_LOG}" -eq 0 ]]; then
        # print_output "[*] Removing empty log file: $LOG_FILE_" "no_log"
        rm "${LOG_FILE_}" 2> /dev/null || true
        continue
      fi
      BIN=$(basename "${LOG_FILE_}")
      BIN=$(echo "${BIN}" | cut -d_ -f3 | sed 's/.txt$//')
      print_output "[+]""${NC}"" Emulated binary ""${GREEN}""${BIN}""${NC}"" generated output in ""${GREEN}""${LOG_FILE_}""${NC}""." "" "${LOG_FILE_}"
    done
  fi
  # if we created a backup for emulation - lets delete it now
  if [[ -d "${LOG_PATH_MODULE}/firmware" ]]; then
    print_output "[*] Remove firmware copy from emulation directory.\\n\\n"
    rm -r "${LOG_PATH_MODULE}"/firmware || true
  fi
}

creating_dev_area() {
  local R_PATH="${1:-}"
  if ! [[ -d "${R_PATH}" ]]; then
    print_output "[-] No R_PATH found ..."
    return
  fi

  print_output "[*] Creating dev area for user mode emulation"

  if ! [[ -e "${R_PATH}""/dev/console" ]] ; then
    print_output "[*] Creating /dev/console"
    mknod -m 622 "${R_PATH}""/dev/console" c 5 1 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/null" ]] ; then
    print_output "[*] Creating /dev/null"
    mknod -m 666 "${R_PATH}""/dev/null" c 1 3 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/zero" ]] ; then
    print_output "[*] Creating /dev/zero"
    mknod -m 666 "${R_PATH}""/dev/zero" c 1 5 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/ptmx" ]] ; then
    print_output "[*] Creating /dev/ptmx"
    mknod -m 666 "${R_PATH}""/dev/ptmx" c 5 2 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/tty" ]] ; then
    print_output "[*] Creating /dev/tty"
    mknod -m 666 "${R_PATH}""/dev/tty" c 5 0 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/random" ]] ; then
    print_output "[*] Creating /dev/random"
    mknod -m 444 "${R_PATH}""/dev/random" c 1 8 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/urandom" ]] ; then
    print_output "[*] Creating /dev/urandom"
    mknod -m 444 "${R_PATH}""/dev/urandom" c 1 9 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/mem" ]] ; then
    print_output "[*] Creating /dev/mem"
    mknod -m 660 "${R_PATH}"/dev/mem c 1 1 2> /dev/null || true
  fi
  if ! [[ -e "${R_PATH}""/dev/kmem" ]] ; then
    print_output "[*] Creating /dev/kmem"
    mknod -m 640 "${R_PATH}"/dev/kmem c 1 2 2> /dev/null || true
  fi
  if ! [[ -e "${R_PATH}""/dev/armem" ]] ; then
    print_output "[*] Creating /dev/armem"
    mknod -m 666 "${R_PATH}"/dev/armem c 1 13 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/tty0" ]] ; then
    print_output "[*] Creating /dev/tty0"
    mknod -m 622 "${R_PATH}"/dev/tty0 c 4 0 2> /dev/null || true
  fi
  if ! [[ -e "${R_PATH}""/dev/ttyS0" ]] ; then
    print_output "[*] Creating /dev/ttyS0 - ttyS3"
    mknod -m 660 "${R_PATH}"/dev/ttyS0 c 4 64 2> /dev/null || true
    mknod -m 660 "${R_PATH}"/dev/ttyS1 c 4 65 2> /dev/null || true
    mknod -m 660 "${R_PATH}"/dev/ttyS2 c 4 66 2> /dev/null || true
    mknod -m 660 "${R_PATH}"/dev/ttyS3 c 4 67 2> /dev/null || true
  fi

  if ! [[ -e "${R_PATH}""/dev/adsl0" ]] ; then
    print_output "[*] Creating /dev/adsl0"
    mknod -m 644 "${R_PATH}"/dev/adsl0 c 100 0 2> /dev/null || true
  fi
  if ! [[ -e "${R_PATH}""/dev/ppp" ]] ; then
    print_output "[*] Creating /dev/ppp"
    mknod -m 644 "${R_PATH}"/dev/ppp c 108 0 2> /dev/null || true
  fi
  if ! [[ -e "${R_PATH}""/dev/hidraw0" ]] ; then
    print_output "[*] Creating /dev/hidraw0"
    mknod -m 666 "${R_PATH}"/dev/hidraw0 c 251 0 2> /dev/null || true
  fi

  if ! [[ -d "${R_PATH}"/dev/mtd ]]; then
    print_output "[*] Creating and populating /dev/mtd"
    mkdir -p "${R_PATH}"/dev/mtd 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/0 c 90 0 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/1 c 90 2 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/2 c 90 4 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/3 c 90 6 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/4 c 90 8 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/5 c 90 10 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/6 c 90 12 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/7 c 90 14 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/8 c 90 16 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/9 c 90 18 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtd/10 c 90 20 2> /dev/null || true
  fi

  mknod -m 644 "${R_PATH}"/dev/mtd0 c 90 0 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr0 c 90 1 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd1 c 90 2 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr1 c 90 3 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd2 c 90 4 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr2 c 90 5 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd3 c 90 6 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr3 c 90 7 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd4 c 90 8 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr4 c 90 9 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd5 c 90 10 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr5 c 90 11 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd6 c 90 12 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr6 c 90 13 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd7 c 90 14 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr7 c 90 15 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd8 c 90 16 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr8 c 90 17 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd9 c 90 18 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr9 c 90 19 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtd10 c 90 20 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdr10 c 90 21 2> /dev/null || true

  if ! [[ -d "${R_PATH}"/dev/mtdblock ]]; then
    print_output "[*] Creating and populating /dev/mtdblock"
    mkdir -p "${R_PATH}"/dev/mtdblock 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/0 b 31 0 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/1 b 31 1 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/2 b 31 2 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/3 b 31 3 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/4 b 31 4 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/5 b 31 5 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/6 b 31 6 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/7 b 31 7 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/8 b 31 8 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/9 b 31 9 2> /dev/null || true
    mknod -m 644 "${R_PATH}"/dev/mtdblock/10 b 31 10 2> /dev/null || true
  fi

  mknod -m 644 "${R_PATH}"/dev/mtdblock0 b 31 0 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock1 b 31 1 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock2 b 31 2 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock3 b 31 3 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock4 b 31 4 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock5 b 31 5 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock6 b 31 6 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock7 b 31 7 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock8 b 31 8 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock9 b 31 9 2> /dev/null || true
  mknod -m 644 "${R_PATH}"/dev/mtdblock10 b 31 10 2> /dev/null || true

  if ! [[ -d "${R_PATH}"/dev/tts ]]; then
    print_output "[*] Creating and populating /dev/tts"
    mkdir -p "${R_PATH}"/dev/tts 2> /dev/null || true
    mknod -m 660 "${R_PATH}"/dev/tts/0 c 4 64 2> /dev/null || true
    mknod -m 660 "${R_PATH}"/dev/tts/1 c 4 65 2> /dev/null || true
    mknod -m 660 "${R_PATH}"/dev/tts/2 c 4 66 2> /dev/null || true
    mknod -m 660 "${R_PATH}"/dev/tts/3 c 4 67 2> /dev/null || true
  fi

  chown -v root:tty "${R_PATH}""/dev/"{console,ptmx,tty} > /dev/null 2>&1 || true
}


#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Mihai Macarie

# Description:  Preparation for testing firmware:
#                 Check log directory
#                 Excluding paths
#                 Check architecture
#                 Binary array
#                 etc path handling
#                 Check firmware
#               Access:
#                 firmware root path via $FIRMWARE_PATH

log_folder() {
  if [[ ${ONLY_DEP} -eq 0 ]] && [[ -d "${LOG_DIR}" ]]; then
    # If RESCAN_SBOM is enabled, skip log directory deletion prompt and reuse existing directory
    if [[ "${RESCAN_SBOM}" -eq 1 ]]; then
      print_output "[*] Rescanning SBOM using existing log directory ${ORANGE}${LOG_DIR}${NC}" "no_log"
      return
    fi
    export RESTART=0          # indicator for testing unfinished tests again
    local lNOT_FINISHED=0     # identify unfinished firmware tests
    local lPOSSIBLE_RESTART=0 # used for testing the checksums of the firmware with stored checksum
    local lUSER_ANSWER="n"
    local lD_LOG_FILES_ARR=()
    local lD_LOG_FILE=""
    local lSTORED_SHA512=""
    local lFW_SHA512=""

    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    There are files in the specified directory: ""${LOG_DIR}"
    echo -e "    You can now delete the content here or start the tool again and specify a different directory."

    if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; then
      if check_emba_ended; then
        print_output "[*] A finished EMBA firmware test was found in the log directory" "no_log"
      elif grep -q "System emulation phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}system emulation phase${NC} already finished" "no_log"
        lNOT_FINISHED=1
      elif grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}testing phase${NC} already finished" "no_log"
        lNOT_FINISHED=1
      elif grep -q "Pre-checking phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory - ${ORANGE}pre-checking phase${NC} already finished" "no_log"
        lNOT_FINISHED=1
      else
        print_output "[*] A ${ORANGE}NOT${NC} finished EMBA firmware test was found in the log directory" "no_log"
        lNOT_FINISHED=1
      fi
    fi

    # we check the found sha512 hash with the firmware to test:
    # shellcheck disable=SC2153
    if [[ -f "${CSV_DIR}"/p02_firmware_bin_file_check.csv ]] && [[ -f "${FIRMWARE_PATH}" ]] && grep -q "SHA512" "${CSV_DIR}"/p02_firmware_bin_file_check.csv; then
      lSTORED_SHA512=$(grep "SHA512" "${CSV_DIR}"/p02_firmware_bin_file_check.csv | cut -d\; -f2 | sort -u)
      lFW_SHA512=$(sha512sum "${FIRMWARE_PATH}" | awk '{print $1}')
      if [[ "${lSTORED_SHA512}" == "${lFW_SHA512}" ]]; then
        # the found analysis is for the same firmware
        lPOSSIBLE_RESTART=1
      fi
    elif [[ -f "${P02_LOG_DIR}"/firmware_hashes.log ]] && [[ -d "${FIRMWARE_PATH}" ]]; then
      print_output "[*] Found firmware directory and hashes file -> checking against the provided firmware directory (${FIRMWARE_PATH}) if a restart would be possible" "no_log"
      find "${FIRMWARE_PATH}" -type f -exec md5sum {} \; | sort -u | awk '{print $1}' >"${P02_LOG_DIR}/firmware_hashes_restarter.log" || true
      # we just diff the file checksums to have a quick idea if we can restart the scan or not
      if diff -q "${P02_LOG_DIR}/firmware_hashes.log" "${P02_LOG_DIR}/firmware_hashes_restarter.log"; then
        lPOSSIBLE_RESTART=1
      fi
    fi
    echo -e "\\n${ORANGE}Delete content of log directory: ${LOG_DIR} ?${NC}\\n"
    if [[ "${lNOT_FINISHED}" -eq 1 ]] && [[ "${lPOSSIBLE_RESTART}" -eq 1 ]]; then
      print_output "[*] If you answer with ${ORANGE}n${NC}o, EMBA tries to process the unfinished test${NC}" "no_log"
    fi

    if [[ ${OVERWRITE_LOG} -eq 1 ]]; then
      lUSER_ANSWER="y"
    else
      read -p "(Y/n)  " -r lUSER_ANSWER
    fi
    case ${lUSER_ANSWER:0:1} in
    y | Y | "")
      if mount | grep "${LOG_DIR}" | grep -e "proc\|sys\|run" >/dev/null; then
        print_ln "no_log"
        print_output "[!] We found unmounted areas from a former emulation process in your log directory ${LOG_DIR}." "no_log"
        print_output "[!] You should unmount this stuff manually:\\n" "no_log"
        print_output "$(indent "$(mount | grep "${LOG_DIR}")")" "no_log"
        echo -e "\\n${RED}Terminate EMBA${NC}\\n"
        exit 1
      elif mount | grep "${LOG_DIR}" >/dev/null; then
        print_ln "no_log"
        print_output "[!] We found unmounted areas in your log directory ${LOG_DIR}." "no_log"
        print_output "[!] If EMBA is failing check this manually:\\n" "no_log"
        print_output "$(indent "$(mount | grep "${LOG_DIR}")")" "no_log"
      else
        rm -R "${LOG_DIR:?}/"* 2>/dev/null || true
        echo -e "\\n${GREEN}Successfully deleted: ${ORANGE}${LOG_DIR}${NC}\\n"
      fi
      ;;
    n | N)
      if [[ "${lNOT_FINISHED}" -eq 1 ]] && [[ -f "${LOG_DIR}"/backup_vars.log ]] && [[ "${lPOSSIBLE_RESTART}" -eq 1 ]]; then
        print_output "[*] EMBA tries to process the unfinished test" "no_log"
        if ! [[ -d "${TMP_DIR}" ]]; then
          mkdir "${TMP_DIR}"
        fi
        touch "${TMP_DIR}"/restart_emba
      else
        echo -e "\\n${RED}Terminate EMBA${NC}\\n"
        exit 1
      fi
      ;;
    *)
      echo -e "\\n${RED}Terminate EMBA${NC}\\n"
      exit 1
      ;;
    esac
  fi

  readarray -t lD_LOG_FILES_ARR < <(find . \( -path ./external -o -path ./config -o -path ./licenses -o -path ./tools -o -path ./EMBA-Non-free -o -path ./tests \) -prune -false -o \( -name "*.txt" -o -name "*.log" \) | head -100)
  if [[ ${USE_DOCKER} -eq 1 && ${#lD_LOG_FILES_ARR[@]} -gt 0 ]]; then
    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    It appears that there are log files in the EMBA directory.\\n    You should move these files to another location where they won't be exposed to the Docker container."
    for lD_LOG_FILE in "${lD_LOG_FILES_ARR[@]}"; do
      echo -e "        ""$(orange "${lD_LOG_FILE}")"
    done
    echo -e "\\n${ORANGE}Continue to run EMBA and ignore this warning?${NC}\\n"
    read -p "(Y/n)  " -r lUSER_ANSWER
    case ${lUSER_ANSWER:0:1} in
    y | Y | "")
      print_ln "no_log"
      ;;
    *)
      echo -e "\\n${RED}Terminate EMBA${NC}\\n"
      exit 1
      ;;
    esac
  fi
}

set_exclude() {
  export EXCLUDE_PATHS=""
  export EXCLUDE=()

  if [[ "${FIRMWARE_PATH}" == "/" ]]; then
    EXCLUDE=("${EXCLUDE[@]}" "/proc" "/sys" "$(pwd)")
    print_output "[!] Apparently you want to test your live system. This can lead to errors. Please report the bugs so the software can be fixed." "no_log"
  fi

  print_ln "no_log"

  # exclude paths from testing and set EXCL_FIND for find command (prune paths dynamicially)
  EXCLUDE_PATHS="$(set_excluded_path)"
  export EXCL_FIND=()
  local lEXCL_TMP
  lEXCL_TMP="$(get_excluded_find "${EXCLUDE_PATHS}")"
  lEXCL_TMP="${lEXCL_TMP//$'\r'/ }"
  lEXCL_TMP="${lEXCL_TMP//$'\n'/}"
  IFS=" " read -r -a EXCL_FIND <<<"${lEXCL_TMP}"
  print_excluded
}

invalidate_p99_path_cache() {
  local lBACKUP_DIR=""
  local lOLD_PATH=""
  if [[ ! -e "${P99_CSV_LOG}" && ! -e "${TMP_DIR}/p99_md5sum_done" && ! -e "${TMP_DIR}/p99_md5sum_done.initialized" ]]; then
    return 0
  fi
  # Keep old records/index recoverable when upgrading an interrupted codec run
  # or when final cleanup changed paths that were already indexed.
  lBACKUP_DIR="$(mktemp -d "${CSV_DIR}/p99_path_cleanup.XXXXXX")" || return 1
  for lOLD_PATH in "${P99_CSV_LOG}" "${TMP_DIR}/p99_md5sum_done" "${TMP_DIR}/p99_md5sum_done.initialized"; do
    if [[ -e "${lOLD_PATH}" ]]; then
      mv -T -- "${lOLD_PATH}" "${lBACKUP_DIR}/${lOLD_PATH##*/}" || return 1
    fi
  done
  ROOT_PATH=()
  print_output "[*] Rebuilding backend after path cleanup; old data saved in ${lBACKUP_DIR}" "no_log"
}

initialize_p99_hash_index() {
  local lINDEX_DIR="${TMP_DIR}/p99_md5sum_done"
  local lINDEX_READY="${TMP_DIR}/p99_md5sum_done.initialized"
  local lINDEX_LOCK="${TMP_DIR}/p99_md5sum_done.lock"
  local lHASH_PATTERN=';([[:xdigit:]]{32});+$'
  local lCSV_LINE=""
  local lMD5SUM=""
  local lPREFIX=""
  local lSHARD_ID=0
  local lSTATUS=0
  local lNOCLOBBER=0
  local lSHARD_DIRS=()

  if [[ -f "${lINDEX_READY}" ]]; then
    return
  fi
  mkdir -p "${lINDEX_DIR}"

  # Initialization is lazy because this helper is used from several extractor
  # modules. Only the first worker imports restart hashes; later workers perform
  # a single marker lookup and avoid scanning the growing CSV entirely.
  if [[ -o noclobber ]]; then
    lNOCLOBBER=1
    set +o noclobber
  fi
  (
    flock -x 9 || exit 1
    if [[ -f "${lINDEX_READY}" ]]; then
      exit 0
    fi

    for ((lSHARD_ID = 0; lSHARD_ID < 256; lSHARD_ID++)); do
      printf -v lPREFIX '%02x' "${lSHARD_ID}"
      lSHARD_DIRS+=("${lINDEX_DIR}/${lPREFIX}")
    done
    mkdir -p "${lSHARD_DIRS[@]}"

    if [[ -f "${P99_CSV_LOG}" ]]; then
      while IFS= read -r lCSV_LINE; do
        if [[ "${lCSV_LINE}" =~ ${lHASH_PATTERN} ]]; then
          lMD5SUM="${BASH_REMATCH[1],,}"
          : >"${lINDEX_DIR}/${lMD5SUM:0:2}/${lMD5SUM}"
        fi
      done <"${P99_CSV_LOG}"
    fi
    : >"${lINDEX_READY}"
  ) 9>"${lINDEX_LOCK}" || lSTATUS="$?"
  if [[ "${lNOCLOBBER}" -eq 1 ]]; then
    set -o noclobber
  fi
  return "${lSTATUS}"
}

binary_architecture_threader() {
  local lBINARY="${1:-}"
  local lSOURCE_MODULE="${2:-}"
  local lMD5SUM="${3:-}"
  if [[ "${lBINARY}" == *".raw" ]]; then
    return
  fi
  if [[ -z "${lMD5SUM}" ]]; then
    lMD5SUM="$(md5sum "${lBINARY}" || print_output "[-] Checksum error for binary ${lBINARY}" "no_log")"
    # GNU md5sum prefixes escaped output with a backslash when the filename
    # contains characters such as a backslash or newline.
    lMD5SUM="${lMD5SUM#\\}"
    lMD5SUM="${lMD5SUM/\ */}"
  else
    lMD5SUM="${lMD5SUM,,}"
  fi
  if ! [[ "${lMD5SUM}" =~ ^[[:xdigit:]]{32}$ ]]; then
    return
  fi
  if ! claim_p99_hash "${lMD5SUM}"; then
    return
  fi
  analyze_binary_architecture "${lBINARY}" "${lSOURCE_MODULE}" "${lMD5SUM}"
}

claim_p99_hash() {
  local lMD5SUM="${1:-}"
  # Workers pass their initialized marker explicitly; standalone calls use an
  # empty local cache instead of assigning a caller-scoped or global variable.
  local lP99_HASH_INDEX_INITIALIZED_FOR="${2:-}"
  local lMD5SUM_INDEX=""
  local lINDEX_READY="${TMP_DIR}/p99_md5sum_done.initialized"
  local lNOCLOBBER=0

  if ! [[ "${lMD5SUM}" =~ ^[[:xdigit:]]{32}$ ]]; then
    return 1
  fi
  lMD5SUM="${lMD5SUM,,}"
  if [[ "${lP99_HASH_INDEX_INITIALIZED_FOR:-}" != "${lINDEX_READY}" ]]; then
    if ! initialize_p99_hash_index; then
      print_output "[-] Failed to initialize P99 hash index" "no_log"
      return 1
    fi
    lP99_HASH_INDEX_INITIALIZED_FOR="${lINDEX_READY}"
  fi

  lMD5SUM_INDEX="${TMP_DIR}/p99_md5sum_done/${lMD5SUM:0:2}"
  # Atomically claim a hash. Filesystem lookups avoid scanning an ever-growing
  # hash log for every extracted file and prevent races between workers.
  if [[ -o noclobber ]]; then
    lNOCLOBBER=1
  else
    set -o noclobber
  fi
  if ! : 2>/dev/null >"${lMD5SUM_INDEX}/${lMD5SUM}"; then
    if [[ "${lNOCLOBBER}" -eq 0 ]]; then
      set +o noclobber
    fi
    return 1
  fi
  if [[ "${lNOCLOBBER}" -eq 0 ]]; then
    set +o noclobber
  fi
  print_dot
}

analyze_binary_architecture() {
  local lBINARY="${1:-}"
  local lSOURCE_MODULE="${2:-}"
  local lMD5SUM="${3:-}"
  local D_FILE_OUTPUT="${4:-}"
  local lD_FLAGS_CNT=""
  local lD_MACHINE="NA"
  local lD_CLASS="NA"
  local lD_DATA="NA"
  local lD_ARCH_GUESSED="NA"

  if [[ -z "${D_FILE_OUTPUT}" ]]; then
    D_FILE_OUTPUT=$(file -b -- "${lBINARY}")
  fi
  if [[ "${D_FILE_OUTPUT}" == *"ELF"* ]]; then
    # noreorder, pic, cpic, o32, mips32
    local lREADELF_H_ARR=()
    local lREADELF_LINE=""
    local lCOMMENT_VALUE=""
    local lCOMMENT_KEY=""
    local lCOMMENT_EXISTING=""
    local lCOMMENT_ID=0
    local lCOMMENT_SORT_ID=0
    local lCOMMENT_DUPLICATE=0
    local lIN_COMMENT_SECTION=0
    local lCOMMENT_VALUES=()
    local lCOMMENT_FIELDS=()
    local lCOMMENT_SORTED=()

    mapfile -t lREADELF_H_ARR < <(readelf -W -h -p .comment "${lBINARY}" 2>/dev/null || true)
    for lREADELF_LINE in "${lREADELF_H_ARR[@]}"; do
      if [[ "${lREADELF_LINE}" == *"String dump"* ]]; then
        lIN_COMMENT_SECTION=1
        lCOMMENT_VALUES+=("  ")
        continue
      fi
      if [[ "${lIN_COMMENT_SECTION}" -eq 1 ]]; then
        IFS=$' \t\n' read -r -a lCOMMENT_FIELDS <<<"${lREADELF_LINE}"
        lCOMMENT_VALUES+=("${lCOMMENT_FIELDS[2]:-} ${lCOMMENT_FIELDS[3]:-} ${lCOMMENT_FIELDS[4]:-}")
        continue
      fi
      case "${lREADELF_LINE}" in
      *"Flags:"*)
        lD_FLAGS_CNT="${lREADELF_LINE// /}"
        lD_FLAGS_CNT="${lD_FLAGS_CNT/*Flags:/}"
        lD_FLAGS_CNT="${lD_FLAGS_CNT/0x0/}"
        ;;
      *"Machine:"*)
        lD_MACHINE="${lREADELF_LINE// /}"
        lD_MACHINE="${lD_MACHINE/*Machine:/}"
        ;;
      *"Class:"*)
        lD_CLASS="${lREADELF_LINE/*Class:/}"
        lD_CLASS="${lD_CLASS#"${lD_CLASS%%[![:space:]]*}"}"
        ;;
      *"Data:"*)
        lD_DATA="${lREADELF_LINE/*Data:/}"
        lD_DATA="${lD_DATA#"${lD_DATA%%[![:space:]]*}"}"
        ;;
      esac
    done
    lD_ARCH_GUESSED=""
    for lCOMMENT_VALUE in "${lCOMMENT_VALUES[@]}"; do
      lCOMMENT_DUPLICATE=0
      for lCOMMENT_EXISTING in "${lCOMMENT_SORTED[@]}"; do
        if [[ "${lCOMMENT_VALUE}" == "${lCOMMENT_EXISTING}" ]]; then
          lCOMMENT_DUPLICATE=1
          break
        fi
      done
      if [[ "${lCOMMENT_DUPLICATE}" -eq 1 ]]; then
        continue
      fi
      lCOMMENT_SORTED+=("${lCOMMENT_VALUE}")
    done
    # Preserve sort -u ordering without starting grep/awk/sort/tr for each ELF.
    for ((lCOMMENT_ID = 1; lCOMMENT_ID < ${#lCOMMENT_SORTED[@]}; lCOMMENT_ID++)); do
      lCOMMENT_KEY="${lCOMMENT_SORTED[lCOMMENT_ID]}"
      lCOMMENT_SORT_ID=$((lCOMMENT_ID - 1))
      while [[ "${lCOMMENT_SORT_ID}" -ge 0 && "${lCOMMENT_SORTED[lCOMMENT_SORT_ID]}" > "${lCOMMENT_KEY}" ]]; do
        lCOMMENT_SORTED[lCOMMENT_SORT_ID + 1]="${lCOMMENT_SORTED[lCOMMENT_SORT_ID]}"
        lCOMMENT_SORT_ID=$((lCOMMENT_SORT_ID - 1))
      done
      lCOMMENT_SORTED[lCOMMENT_SORT_ID + 1]="${lCOMMENT_KEY}"
    done
    for lCOMMENT_VALUE in "${lCOMMENT_SORTED[@]}"; do
      lD_ARCH_GUESSED+="${lCOMMENT_VALUE},"
    done
  fi

  write_csv_log_to_path "${P99_CSV_LOG}" "${lSOURCE_MODULE}" "${lBINARY}" "${lD_CLASS}" "${lD_DATA}" "${lD_MACHINE}" "${lD_FLAGS_CNT}" "${lD_ARCH_GUESSED}" "${D_FILE_OUTPUT//\;/,}" "${lMD5SUM}"
}

populate_p99_backend() {
  local lFILES_LIST="${1:-}"
  local lSOURCE_MODULE="${2:-}"
  local lFILE_COUNT="${3:-0}"
  local lMAX_THREADS="${MAX_MOD_THREADS:-1}"
  local lWORKER_COUNT=0
  local lWORKER_DIR=""
  local lWORKER_FILE=""
  local lSTATUS=0
  local lWORKER_FILES=()
  local lWORKER_PIDS=()

  if ! [[ "${lMAX_THREADS}" =~ ^[1-9][0-9]*$ ]]; then
    lMAX_THREADS=1
  fi
  lWORKER_COUNT=$((2 * lMAX_THREADS))
  if [[ "${lFILE_COUNT}" -lt "${lWORKER_COUNT}" ]]; then
    lWORKER_COUNT="${lFILE_COUNT}"
  fi
  if [[ "${lWORKER_COUNT}" -lt 1 ]]; then
    return
  fi

  lWORKER_DIR=$(mktemp -d "${TMP_DIR}/p99_backend_workers.XXXXXX") || return
  if ! split -n "r/${lWORKER_COUNT}" -t '\0' -d -a 5 "${lFILES_LIST}" "${lWORKER_DIR}/worker_"; then
    print_output "[-] Failed to partition P99 backend work" "no_log"
    rm -r -- "${lWORKER_DIR}"
    return 1
  fi
  lWORKER_FILES=("${lWORKER_DIR}"/worker_*)

  for lWORKER_FILE in "${lWORKER_FILES[@]}"; do
    p99_backend_worker "${lWORKER_FILE}" "${lSOURCE_MODULE}" &
    lWORKER_PIDS+=("$!")
  done
  wait_for_pid "${lWORKER_PIDS[@]}" || lSTATUS="$?"
  rm -r -- "${lWORKER_DIR}"
  return "${lSTATUS}"
}

p99_backend_worker() {
  local lWORKER_FILE="${1:-}"
  local lSOURCE_MODULE="${2:-}"
  local lHASH_BATCH_SIZE="${P99_HASH_BATCH_SIZE:-128}"
  local lWORKER_HASH_INDEX_CACHE="${TMP_DIR}/p99_md5sum_done.initialized"
  local lMD5_RECORD=""
  local lMD5SUM=""
  local lBINARY=""
  local lFILE_OUTPUT=""
  local lRECORD_ID=0
  local lMD5_RECORDS=()
  local lINPUT_FILES=()
  local lHASHED_FILES=()
  local lHASHES=()
  local lFILE_OUTPUTS=()

  if ! [[ "${lHASH_BATCH_SIZE}" =~ ^[1-9][0-9]*$ ]]; then
    lHASH_BATCH_SIZE=128
  fi
  # Initialize once per worker; pass a read-only cache value to every claim.
  initialize_p99_hash_index || return 1
  # GNU md5sum -z and file -0 -0 produce unescaped, NUL-delimited records.
  # Bounded batches avoid one checksum and one file process per extracted file.
  while mapfile -d '' -n "${lHASH_BATCH_SIZE}" -t lINPUT_FILES && ((${#lINPUT_FILES[@]})); do
    lHASHED_FILES=()
    for lBINARY in "${lINPUT_FILES[@]}"; do
      if [[ "${lBINARY}" != *".raw" ]]; then
        lHASHED_FILES+=("${lBINARY}")
      fi
    done
    if ((${#lHASHED_FILES[@]} == 0)); then
      lINPUT_FILES=()
      continue
    fi

    mapfile -d '' -t lMD5_RECORDS < <(md5sum -z -- "${lHASHED_FILES[@]}" 2>/dev/null || true)
    lHASHED_FILES=()
    lHASHES=()
    for lMD5_RECORD in "${lMD5_RECORDS[@]}"; do
      if [[ "${#lMD5_RECORD}" -lt 35 ]]; then
        continue
      fi
      lMD5SUM="${lMD5_RECORD:0:32}"
      lBINARY="${lMD5_RECORD:34}"
      if claim_p99_hash "${lMD5SUM}" "${lWORKER_HASH_INDEX_CACHE}"; then
        lHASHES+=("${lMD5SUM}")
        lHASHED_FILES+=("${lBINARY}")
      fi
    done
    if ((${#lHASHED_FILES[@]} == 0)); then
      lINPUT_FILES=()
      lMD5_RECORDS=()
      continue
    fi

    mapfile -d '' -t lFILE_OUTPUTS < <(file -0 -0 -b -- "${lHASHED_FILES[@]}" 2>/dev/null || true)
    for ((lRECORD_ID = 0; lRECORD_ID < ${#lHASHED_FILES[@]}; lRECORD_ID++)); do
      lFILE_OUTPUT="${lFILE_OUTPUTS[lRECORD_ID]:-unreadable}"
      analyze_binary_architecture "${lHASHED_FILES[lRECORD_ID]}" "${lSOURCE_MODULE}" "${lHASHES[lRECORD_ID]}" "${lFILE_OUTPUT}"
    done
    lINPUT_FILES=()
    lMD5_RECORDS=()
    lHASHED_FILES=()
    lHASHES=()
    lFILE_OUTPUTS=()
  done <"${lWORKER_FILE}"
}

architecture_check() {
  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_output "[-] WARNING: Architecture auto detection and backend data population not possible\\n"
    return
  fi

  if [[ ${ARCH_CHECK} -eq 1 ]]; then
    print_output "[*] Architecture auto detection and backend data population for ${ORANGE}${#ALL_FILES_ARR[@]}${NC} files (could take some time)\\n"
    # lARCH_MIPS_CNT -> 32 bit MIPS
    local lARCH_MIPS_CNT=0
    local lARCH_ARM_CNT=0
    local lARCH_ARM64_CNT=0
    local lARCH_X64_CNT=0
    local lARCH_X86_CNT=0
    local lARCH_PPC_CNT=0
    local lARCH_NIOS2_CNT=0
    local lARCH_MIPS64R2_CNT=0
    local lARCH_MIPS64_III_CNT=0
    local lARCH_MIPS64v1_CNT=0
    local lARCH_MIPS64_N32_CNT=0
    local lARCH_RISCV_CNT=0
    local lARCH_PPC64_CNT=0
    local lARCH_QCOM_DSP6_CNT=0
    local lARCH_TRICORE_CNT=0
    local lD_END_LE_CNT=0
    local lD_END_BE_CNT=0
    export ARM_HF=0
    export ARM_SF=0
    export D_END="NA"
    local lBINARY=""
    local D_FILE_OUTPUT=""

    # sort and make P99_CSV_LOG unique
    sort -u -t';' -k9,9 -o "${P99_CSV_LOG}" "${P99_CSV_LOG}"
    # this needs to be added to the first line
    # write_csv_log_to_path "CSV log file" "SOURCE MODULE" "FILE" "BINARY_CLASS" "END_DATA" "MACHINE-TYPE" "BINARY_FLAGS" "ARCH_GUESSED" "ELF-DATA" "MD5SUM"

    lARCH_MIPS64_N32_CNT=$(grep -c "N32 MIPS64 rel2" "${P99_CSV_LOG}" || true)
    lARCH_MIPS64R2_CNT=$(grep -c "MIPS64 rel2" "${P99_CSV_LOG}" || true)
    lARCH_MIPS64_III_CNT=$(grep -c "64-bit.*MIPS-III" "${P99_CSV_LOG}" || true)
    lARCH_MIPS64v1_CNT=$(grep -c "64-bit.*MIPS64 version 1" "${P99_CSV_LOG}" || true)
    lARCH_MIPS_CNT=$(grep -c "32-bit.*MIPS" "${P99_CSV_LOG}" || true)
    lARCH_ARM64_CNT=$(grep -c "ARM aarch64" "${P99_CSV_LOG}" || true)
    lARCH_ARM_CNT=$(grep -c "32-bit.*ARM" "${P99_CSV_LOG}" || true)
    if [[ "${lARCH_ARM64_CNT}" -gt 0 || "${lARCH_ARM_CNT}" -gt 0 ]]; then
      ARM_HF=$(cut -d ';' -f5 "${P99_CSV_LOG}" | grep -c "hard-float" || true)
      ARM_SF=$(cut -d ';' -f5 "${P99_CSV_LOG}" | grep -c "soft-float" || true)
    fi
    lARCH_X64_CNT=$(grep -c "x86-64" "${P99_CSV_LOG}" || true)
    lARCH_X86_CNT=$(grep -c "80386" "${P99_CSV_LOG}" || true)
    lARCH_PPC64_CNT=$(grep -c "64-bit PowerPC" "${P99_CSV_LOG}" || true)
    if [[ "${lARCH_PPC64_CNT}" -eq 0 ]]; then
      lARCH_PPC_CNT=$(grep -c "PowerPC" "${P99_CSV_LOG}" || true)
    fi
    lARCH_NIOS2_CNT=$(grep -c "Altera Nios II" "${P99_CSV_LOG}" || true)
    lARCH_RISCV_CNT=$(grep -c "UCB RISC-V" "${P99_CSV_LOG}" || true)
    lARCH_QCOM_DSP6_CNT=$(grep -c "QUALCOMM DSP6" "${P99_CSV_LOG}" || true)
    lARCH_TRICORE_CNT=$(grep -c "Tricore" "${P99_CSV_LOG}" || true)

    lD_END_BE_CNT=$(cut -d ';' -f8 "${P99_CSV_LOG}" | grep -c "MSB" || true)
    lD_END_LE_CNT=$(cut -d ';' -f8 "${P99_CSV_LOG}" | grep -c "LSB" || true)

    if [[ $((lARCH_MIPS_CNT + lARCH_ARM_CNT + lARCH_X64_CNT + lARCH_X86_CNT + lARCH_PPC_CNT + lARCH_NIOS2_CNT + lARCH_MIPS64R2_CNT + lARCH_MIPS64_III_CNT + lARCH_MIPS64_N32_CNT + lARCH_ARM64_CNT + lARCH_MIPS64v1_CNT + lARCH_RISCV_CNT + lARCH_PPC64_CNT + lARCH_QCOM_DSP6_CNT + lARCH_TRICORE_CNT)) -gt 0 ]]; then
      print_output "$(indent "$(orange "Architecture Count")")"
      if [[ ${lARCH_MIPS_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "MIPS          ""${lARCH_MIPS_CNT}")")"; fi
      if [[ ${lARCH_MIPS64R2_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "MIPS64r2     ""${lARCH_MIPS64R2_CNT}")")"; fi
      if [[ ${lARCH_MIPS64_III_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "MIPS64 III     ""${lARCH_MIPS64_III_CNT}")")"; fi
      if [[ ${lARCH_MIPS64_N32_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "MIPS64 N32     ""${lARCH_MIPS64_N32_CNT}")")"; fi
      if [[ ${lARCH_MIPS64v1_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "MIPS64v1      ""${lARCH_MIPS64v1_CNT}")")"; fi
      if [[ ${lARCH_ARM_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "ARM           ""${lARCH_ARM_CNT}")")"; fi
      if [[ ${lARCH_ARM64_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "ARM64         ""${lARCH_ARM64_CNT}")")"; fi
      if [[ ${lARCH_X64_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "x64           ""${lARCH_X64_CNT}")")"; fi
      if [[ ${lARCH_X86_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "x86           ""${lARCH_X86_CNT}")")"; fi
      if [[ ${lARCH_PPC_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "PPC           ""${lARCH_PPC_CNT}")")"; fi
      if [[ ${lARCH_PPC64_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "PPC64         ""${lARCH_PPC64_CNT}")")"; fi
      if [[ ${lARCH_NIOS2_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "NIOS II       ""${lARCH_NIOS2_CNT}")")"; fi
      if [[ ${lARCH_RISCV_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "RISC-V        ""${lARCH_RISCV_CNT}")")"; fi
      if [[ ${lARCH_QCOM_DSP6_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "Qualcom DSP6  ""${lARCH_QCOM_DSP6_CNT}")")"; fi
      if [[ ${lARCH_TRICORE_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "Tricore       ""${lARCH_TRICORE_CNT}")")"; fi

      if [[ ${lARCH_MIPS_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_PPC_CNT} ]] &&
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] &&
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_ARM64_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_RISCV_CNT} ]] &&
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_PPC64_CNT} ]] && [[ ${lARCH_MIPS_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] &&
        [[ ${lARCH_MIPS_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS"
      elif [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_X86_CNT} ]] &&
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] &&
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_ARM_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_ARM_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="ARM"
      elif [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_X86_CNT} ]] &&
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] &&
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_ARM_CNT} ]] &&
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_ARM64_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_ARM64_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="ARM64"
      elif [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_X86_CNT} ]] &&
        [[ ${lARCH_X64_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] &&
        [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_X64_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_X64_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_X64_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="x64"
      elif [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_X64_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_ARM_CNT} ]] &&
        [[ ${lARCH_X86_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] &&
        [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_X86_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_X86_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_X86_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="x86"
      elif [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_NIOS2_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] &&
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_PPC_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_PPC_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="PPC"
      elif [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] &&
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_NIOS2_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="NIOS2"
      elif [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS64_III_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64R2_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64R2"
      elif [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64_III_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64_3"
      elif [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64_N32_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64N32"
      elif [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_RISCV_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_MIPS64v1_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="MIPS64v1"
      elif [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_PPC64_CNT} ]] &&
        [[ ${lARCH_RISCV_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_RISCV_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="RISCV"
      elif [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_RISCV_CNT} ]] &&
        [[ ${lARCH_PPC64_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]] && [[ ${lARCH_PPC64_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="PPC64"
      elif [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_RISCV_CNT} ]] &&
        [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_PPC64_CNT} ]] && [[ ${lARCH_QCOM_DSP6_CNT} -gt ${lARCH_TRICORE_CNT} ]]; then
        D_ARCH="QCOM_DSP6"
      elif [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_X64_CNT} ]] &&
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_X86_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_PPC_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_NIOS2_CNT} ]] &&
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS64R2_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_ARM_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_ARM64_CNT} ]] &&
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS64_N32_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_MIPS64v1_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_RISCV_CNT} ]] &&
        [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_PPC64_CNT} ]] && [[ ${lARCH_TRICORE_CNT} -gt ${lARCH_QCOM_DSP6_CNT} ]]; then
        D_ARCH="TRICORE"
      else
        D_ARCH="unknown"
      fi

      if [[ $((lD_END_BE_CNT + lD_END_LE_CNT)) -gt 0 ]]; then
        print_ln
        print_output "$(indent "$(orange "Endianness  Count")")"
        if [[ ${lD_END_BE_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "Big endian          ""${lD_END_BE_CNT}")")"; fi
        if [[ ${lD_END_LE_CNT} -gt 0 ]]; then print_output "$(indent "$(orange "Little endian          ""${lD_END_LE_CNT}")")"; fi
      fi
      if [[ $((ARM_SF + ARM_HF)) -gt 0 ]]; then
        print_ln
        print_output "$(indent "$(orange "ARM Hardware/Software floating Count")")"
        if [[ ${ARM_SF} -gt 0 ]]; then print_output "$(indent "$(orange "Software floating          ""${ARM_SF}")")"; fi
        if [[ ${ARM_HF} -gt 0 ]]; then print_output "$(indent "$(orange "Hardware floating          ""${ARM_HF}")")"; fi
      fi

      if [[ ${lD_END_LE_CNT} -gt ${lD_END_BE_CNT} ]]; then
        D_END="EL"
      elif [[ ${lD_END_BE_CNT} -gt ${lD_END_LE_CNT} ]]; then
        D_END="EB"
      else
        D_END="NA"
      fi

      print_ln

      if [[ $((lD_END_BE_CNT + lD_END_LE_CNT)) -gt 0 ]]; then
        print_output "$(indent "Detected architecture and endianness of the firmware: ""${ORANGE}""${D_ARCH}"" / ""${D_END}""${NC}")""\\n"
        export D_END
      else
        print_output "$(indent "Detected architecture of the firmware: ""${ORANGE}""${D_ARCH}""${NC}")""\\n"
      fi

      if [[ -n "${ARCH:-}" ]]; then
        if [[ "${ARCH}" != "${D_ARCH}" ]]; then
          print_output "[!] Your set architecture (""${ARCH}"") is different from the automatically detected one. The set architecture will be used."
        fi
      else
        print_output "[*] No architecture was enforced, so the automatically detected one is used." "no_log"
        export ARCH=""
        ARCH="${D_ARCH}"
      fi
    elif [[ -n "${EFI_ARCH}" ]]; then
      print_output "$(indent "Detected architecture of the UEFI firmware: ""${ORANGE}""${EFI_ARCH}""${NC}")""\\n"
      export ARCH=""
      ARCH="${EFI_ARCH}"
    else
      print_output "$(indent "$(red "Based on binary identification no architecture was detected.")")"
      if [[ -n "${ARCH}" ]]; then
        print_output "[*] Manually enforced architecture (""${ARCH}"") will be used."
      fi
    fi
    backup_var "ARCH" "${ARCH}"
    backup_var "D_END" "${D_END}"

  else
    print_output "[*] Architecture auto detection disabled\\n"
    if [[ -n "${ARCH}" ]]; then
      print_output "[*] Manually enforced architecture (""${ARCH}"") will be used."
    else
      print_output "[!] Since no architecture could be detected, you should set one."
    fi
  fi
}

prepare_all_file_arrays() {
  local lFIRMWARE_PATH="${1:-}"
  echo ""
  print_output "[*] Auto detection of all files with further details for ${ORANGE}${lFIRMWARE_PATH}${NC}\\n"
  export ALL_FILES_ARR=()

  # we exclude all the raw files from binwalk
  # readarray -t ALL_FILES_ARR < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f ! -name "*.raw")
  readarray -t ALL_FILES_ARR < <(cut -d ';' -f2 "${P99_CSV_LOG}" | grep -v "\.raw$")

  # RTOS handling:
  if [[ -f ${lFIRMWARE_PATH} && ${RTOS} -eq 1 ]]; then
    # local lFILE_ARR_RTOS=()
    # readarray -t lFILE_ARR_RTOS < <(find "${OUTPUT_DIR}" -xdev -type f)
    # ALL_FILES_ARR+=( "${lFILE_ARR_RTOS[@]}" )
    ALL_FILES_ARR+=("${lFIRMWARE_PATH}")
  fi
}

prepare_file_arr() {
  local lFIRMWARE_PATH="${1:-}"
  echo ""
  print_output "[*] Unique files auto detection for ${ORANGE}${lFIRMWARE_PATH}${NC}\\n"

  export FILE_ARR=()
  # readarray -t FILE_ARR < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" || true' 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- || true)
  # readarray -t FILE_ARR < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f -exec md5sum {} \; | sort -u -k1,1 | cut -d\  -f3- )
  readarray -t FILE_ARR < <(cut -d ';' -f2 "${P99_CSV_LOG}" | grep -v "\.raw$" || true)
  # RTOS handling:
  if [[ -f ${lFIRMWARE_PATH} && ${RTOS} -eq 1 ]]; then
    # readarray -t FILE_ARR_RTOS < <(find "${OUTPUT_DIR}" -xdev -type f -exec md5sum {} \; | sort -u -k1,1 | cut -d\  -f3- )
    # readarray -t FILE_ARR_RTOS < <(find "${OUTPUT_DIR}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" || true' 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- )
    # FILE_ARR+=( "${FILE_ARR_RTOS[@]}" )
    FILE_ARR+=("${lFIRMWARE_PATH}")
  fi
  print_output "[*] Found ${ORANGE}${#FILE_ARR[@]}${NC} unique files."

  # xdev will do the trick for us:
  # remove ./proc/* executables (for live testing)
  # rm_proc_binary "${FILE_ARR[@]}"
}

prepare_binary_arr() {
  local lFIRMWARE_PATH="${1:-}"
  if ! [[ -d "${lFIRMWARE_PATH}" ]]; then
    return
  fi
  echo ""
  print_output "[*] Unique binary auto detection for ${ORANGE}${lFIRMWARE_PATH}${NC} (could take some time)\\n"

  # lets try to get an unique binary array
  # Necessary for providing BINARIES array (usable in every module)
  export BINARIES=()
  local lBINARIES_TMP_ARR=()
  local lBINARY=""
  local lBIN_MD5=""
  local lMD5_DONE_INT_ARR=()
  # readarray -t BINARIES < <( find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -executable -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  # In some firmwares we miss the exec permissions in the complete firmware. In such a case we try to find ELF files and unique it
  # readarray -t lBINARIES_TMP_ARR < <(find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -exec file {} \; grep "ELF\|PE32" | cut -d: -f1 || true)
  # readarray -t lBINARIES_TMP_ARR < <(find "${lFIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file %' | grep "ELF\|PE32" | cut -d: -f1 2>/dev/null || true)
  readarray -t lBINARIES_TMP_ARR < <(grep ";ELF\|;PE32" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)
  if [[ "${#lBINARIES_TMP_ARR[@]}" -gt 0 ]]; then
    for lBINARY in "${lBINARIES_TMP_ARR[@]}"; do
      if [[ -f "${lBINARY}" ]]; then
        lBIN_MD5=$(md5sum "${lBINARY}" | cut -d\  -f1)
        if [[ ! " ${lMD5_DONE_INT_ARR[*]} " =~ ${lBIN_MD5} ]]; then
          BINARIES+=("${lBINARY}")
          lMD5_DONE_INT_ARR+=("${lBIN_MD5}")
        fi
      fi
    done
    print_output "[*] Found ${ORANGE}${#BINARIES[@]}${NC} unique executables."
  fi

  # remove ./proc/* executables (for live testing)
  # rm_proc_binary "${BINARIES[@]}"
}

prepare_file_arr_limited() {
  local lFIRMWARE_PATH="${1:-}"
  export FILE_ARR_LIMITED=()

  if ! [[ -d "${lFIRMWARE_PATH}" ]]; then
    return
  fi

  echo ""
  print_output "[*] Unique and limited file array generation for ${ORANGE}${lFIRMWARE_PATH}${NC}\\n"

  # readarray -t FILE_ARR_LIMITED < <(find "${lFIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -type f ! \( -iname "*.udeb" -o -iname "*.deb" \
  #  -o -iname "*.ipk" -o -iname "*.pdf" -o -iname "*.php" -o -iname "*.txt" -o -iname "*.doc" -o -iname "*.rtf" -o -iname "*.docx" \
  #  -o -iname "*.htm" -o -iname "*.html" -o -iname "*.md5" -o -iname "*.sha1" -o -iname "*.torrent" -o -iname "*.png" -o -iname "*.svg" \
  #  -o -iname "*.js" -o -iname "*.info" -o -iname "*.md" -o -iname "*.log" -o -iname "*.yml" -o -iname "*.bmp" -o -path "*/\.git/*" \) \
  #  -exec md5sum {} \; | sort -u -k1,1 | cut -d\  -f3-)

  readarray -t FILE_ARR_LIMITED < <(cut -d ';' -f2 "${P99_CSV_LOG}" | grep -v "\.udeb$\|\.deb$\|\.ipk$\|\.pdf$\\|\.php$\|\.txt$\|\.doc$\|\.rtf$\|\.docx\|\.htm$\|\.md5$\|\..sha1$\|\.torrent$\|\.png$\|\.svg$\|\.js$\|\.info$\|\.md$\|\.log$\|\.yml$\|\.bmp$\|\.git\/" | sort -u || true)

}

set_etc_paths() {
  # For the case if ./etc isn't in root of provided firmware or is renamed like e.g. ./etc-ro:
  # search etc paths
  # set them in ETC_PATHS variable
  # If another variable needs a "Extrawurst", you only need to copy 'set_etc_path' function, modify it and change
  # 'mod_path' for project wide path modification
  export ETC_PATHS
  set_etc_path
  print_etc
}

check_firmware() {
  # this detection is only running if we have not found a Linux system:
  local lDIR_COUNT=0
  local lR_PATH=""
  local lL_PATH=""

  if [[ "${RTOS}" -eq 1 ]]; then
    # Check if firmware got normal linux directory structure and warn if not
    # as we already have done some root directory detection we are going to use it now
    local lLINUX_PATHS_ARR=("bin" "boot" "dev" "etc" "home" "lib" "mnt" "opt" "proc" "root" "sbin" "srv" "tmp" "usr" "var")
    if [[ ${#ROOT_PATH[@]} -gt 0 ]]; then
      for lR_PATH in "${ROOT_PATH[@]}"; do
        for lL_PATH in "${lLINUX_PATHS_ARR[@]}"; do
          if [[ -d "${lR_PATH}"/"${lL_PATH}" ]]; then
            ((lDIR_COUNT += 1))
          fi
        done
      done
    else
      # this is needed for directories we are testing
      # in such a case the pre-checking modules are not executed and no RPATH is available
      for lL_PATH in "${lLINUX_PATHS_ARR[@]}"; do
        if [[ -d "${FIRMWARE_PATH}"/"${lL_PATH}" ]]; then
          ((lDIR_COUNT += 1))
        fi
      done
    fi
  fi

  if [[ ${lDIR_COUNT} -lt 5 ]] && [[ "${RTOS}" -eq 1 ]]; then
    print_output "[-] Your firmware does not look like a regular Linux system."
  fi
  if [[ "${RTOS}" -eq 0 ]] || [[ ${lDIR_COUNT} -gt 4 ]]; then
    print_output "[+] Your firmware looks like a regular Linux system."
  fi
}

detect_root_dir_helper() {
  local lSEARCH_PATH="${1:-}"

  print_output "[*] Root directory auto detection for ${ORANGE}${lSEARCH_PATH}${NC} (could take some time)\\n"
  export ROOT_PATH=()
  local lMECHANISM=""
  local lROOTx_PATH_ARR=()
  local lINTERPRETER_FULL_PATH_ARR=()
  local lINTERPRETER_PATH=""
  local lINTERPRETER_FULL_RPATH_ARR=()
  local lR_PATH=""
  local lINTERPRETER_ESCAPED=""
  local lCNT=0

  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_output "[-] No ${P99_CSV_LOG} log file created ... no root directory detection possible"
    return
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 0 ]]; then
    # xargs threading is much faster. Big testcase firmware 9mins vs. 3mins
    # mapfile -t lINTERPRETER_FULL_PATH_ARR < <(find "${lSEARCH_PATH}" -ignore_readdir_race -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file -b % 2>/dev/null' | grep "ELF.*interpreter /" | sed "s/.*interpreter\ //" | sed "s/,\ .*$//" | sort -u || true)
    mapfile -t lINTERPRETER_FULL_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | cut -d ';' -f8 | grep "ELF.*interpreter /" | sed "s/.*interpreter\ //" | sed "s/,\ .*$//" | sort -u || true)

    if [[ "${#lINTERPRETER_FULL_PATH_ARR[@]}" -gt 0 ]]; then
      for lINTERPRETER_PATH in "${lINTERPRETER_FULL_PATH_ARR[@]}"; do
        # now we have a result like this "/lib/ld-uClibc.so.0"
        # lets escape it
        lINTERPRETER_ESCAPED=$(sed -e 's/\//\\\//g' <<<"${lINTERPRETER_PATH}")
        # mapfile -t lINTERPRETER_FULL_RPATH_ARR < <(find "${lSEARCH_PATH}" -ignore_readdir_race -wholename "*${lINTERPRETER_PATH}" 2>/dev/null | sort -u)
        mapfile -t lINTERPRETER_FULL_RPATH_ARR < <(cut -d ';' -f2 "${P99_CSV_LOG}" 2>/dev/null | grep "${lINTERPRETER_PATH}" | sort -u || true)
        for lR_PATH in "${lINTERPRETER_FULL_RPATH_ARR[@]}"; do
          # remove the interpreter path from the full path:
          lR_PATH="${lR_PATH//${lINTERPRETER_ESCAPED}/}"
          # common false positive:
          if [[ -v lR_PATH ]] && [[ -d "${lR_PATH}" ]]; then
            [[ "${lR_PATH}" =~ \/lib\/$ ]] && continue
            ROOT_PATH+=("${lR_PATH}")
            lMECHANISM="binary interpreter"
          fi
        done
      done
    fi

    # mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/busybox" | sed -E 's/\/.?bin\/busybox//')
    mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "bin/busybox" | cut -d ';' -f2 | sed -E 's/\/.?bin\/busybox.*//' | sort -u || true)
    for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
      if [[ -d "${lR_PATH}" ]]; then
        ROOT_PATH+=("${lR_PATH}")
        if [[ -z "${lMECHANISM}" ]]; then
          lMECHANISM="busybox"
        elif [[ -n "${lMECHANISM}" ]] && [[ "${lMECHANISM}" != *"busybox"* ]]; then
          lMECHANISM="${lMECHANISM} / busybox"
        fi
      fi
    done
    # mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/bash" -exec file {} \; | grep "ELF" | cut -d: -f1 | sed -E 's/\/.?bin\/bash//' || true)
    mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "bin/bash" | cut -d ';' -f2 | sed -E 's/\/.?bin\/bash.*//' | sort -u || true)
    for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
      if [[ -d "${lR_PATH}" ]]; then
        ROOT_PATH+=("${lR_PATH}")
        if [[ -z "${lMECHANISM}" ]]; then
          lMECHANISM="shell"
        elif [[ -n "${lMECHANISM}" ]] && [[ "${lMECHANISM}" != *"shell"* ]]; then
          lMECHANISM="${lMECHANISM} / shell"
        fi
      fi
    done
    # mapfile -t lROOTx_PATH_ARR < <(find "${lSEARCH_PATH}" -xdev -path "*bin/sh" -print0|xargs -r -0 -P 16 -I % sh -c 'file % | grep "ELF" | cut -d: -f1 | sed -E "s/\/.?bin\/sh//"' || true)
    mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "bin/sh;" | cut -d ';' -f2 | sed -E 's/\/.?bin\/sh.*//' | sort -u || true)
    for lR_PATH in "${lROOTx_PATH_ARR[@]}"; do
      if [[ -d "${lR_PATH}" ]]; then
        ROOT_PATH+=("${lR_PATH}")
        if [[ -z "${lMECHANISM}" ]]; then
          lMECHANISM="shell"
        elif [[ -n "${lMECHANISM}" ]] && [[ "${lMECHANISM}" != *"shell"* ]]; then
          lMECHANISM="${lMECHANISM} / shell"
        fi
      fi
    done
  fi

  # currently not working: mapfile -t lROOTx_PATH_ARR < <(grep ";${lSEARCH_PATH}.*ELF" "${P99_CSV_LOG}" | grep "/bin/\|/lib/\|/etc/\|/root/\|/dev/\|/opt/\|/proc/\|/lib64\|/boot/\|/home/" | cut -d ';' -f2 | grep "${lSEARCH_PATH}" | sort -u || true)
  # Stream and parse candidates with a shell builtin. Storing the entire list
  # and spawning two awk processes per candidate is costly on large trees.
  while IFS=' ' read -r lCNT lR_PATH; do
    if [[ "${lCNT}" -lt 5 ]]; then
      # we only use paths with more then 4 matches as possible root path
      continue
    fi
    if [[ -d "${lR_PATH}" ]]; then
      ROOT_PATH+=("${lR_PATH}")
      if [[ -z "${lMECHANISM}" ]]; then
        lMECHANISM="dir names"
      elif [[ -n "${lMECHANISM}" ]] && [[ "${lMECHANISM}" != *"dir names"* ]]; then
        lMECHANISM="${lMECHANISM} / dir names"
      fi
    fi
  done < <(find "${lSEARCH_PATH}" -xdev \( -path "*/sbin" -o -path "*/bin" -o -path "*/lib" -o -path "*/etc" -o -path "*/root" -o -path "*/dev" -o -path "*/opt" -o -path "*/proc" -o -path "*/lib64" -o -path "*/boot" -o -path "*/home" \) -exec dirname {} \; | sort | uniq -c | sort -r)

  if [[ ${#ROOT_PATH[@]} -eq 0 ]]; then
    export RTOS=1
    ROOT_PATH+=("${lSEARCH_PATH}")
    lMECHANISM="last resort"
  else
    export RTOS=0
  fi

  if [[ "${#ROOT_PATH[@]}" -gt 0 ]]; then
    mapfile -t ROOT_PATH < <(printf "%s\n" "${ROOT_PATH[@]}" | sed '/^$/d' | sort -u)
  fi
  if [[ -v ROOT_PATH[@] && "${RTOS}" -eq 0 ]]; then
    print_output "[*] Found ${ORANGE}${#ROOT_PATH[@]}${NC} different root directories:"
    write_link "s05#file_dirs"
  fi

  for lR_PATH in "${ROOT_PATH[@]}"; do
    if [[ "${lMECHANISM}" == "last resort" ]]; then
      print_output "[*] Found no real root directory - setting it to: ${ORANGE}${lR_PATH}${NC} via ${ORANGE}${lMECHANISM}${NC}."
    else
      print_output "[+] Found the following root directory: ${ORANGE}${lR_PATH}${GREEN} via ${ORANGE}${lMECHANISM}${GREEN}."
    fi
    write_link "s05#file_dirs"
  done
}

check_init_size() {
  local lSIZE=""

  lSIZE=$(du -b --max-depth=0 "${FIRMWARE_PATH}" | awk '{print $1}' || true)
  if [[ ${lSIZE} -gt 400000000 ]]; then
    print_ln "no_log"
    print_output "[!] WARNING: Your firmware is very big!" "no_log"
    print_output "[!] WARNING: Analysing huge firmwares will take a lot of disk space, RAM and time!" "no_log"
    print_ln "no_log"
  fi
}

# Converts time in the form of 123d or 123h or 123m or 123s to seconds without s -> 123s -> 123
# Parameter: Time in d/h/m/s format
convert_timeformat() {
  local lTIME_TO_CONVERT="${1:-}"

  if [[ "${lTIME_TO_CONVERT}" == *"d" ]]; then
    lTIME_TO_CONVERT=${lTIME_TO_CONVERT//d/}
    lTIME_TO_CONVERT=$((lTIME_TO_CONVERT * 24 * 3600))
  fi
  if [[ "${lTIME_TO_CONVERT}" == *"h" ]]; then
    lTIME_TO_CONVERT=${lTIME_TO_CONVERT//h/}
    lTIME_TO_CONVERT=$((lTIME_TO_CONVERT * 3600))
  fi
  if [[ "${lTIME_TO_CONVERT}" == *"m" ]]; then
    lTIME_TO_CONVERT=${lTIME_TO_CONVERT//m/}
    lTIME_TO_CONVERT=$((lTIME_TO_CONVERT * 60))
  fi
  if [[ "${lTIME_TO_CONVERT}" == *"s" ]]; then
    lTIME_TO_CONVERT=${lTIME_TO_CONVERT//s/}
  fi
  echo "${lTIME_TO_CONVERT}"
}

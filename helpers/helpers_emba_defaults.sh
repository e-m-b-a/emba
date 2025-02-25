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
# Contributor(s): Benedikt Kuehne

# Description: Sets default values for EMBA


set_defaults() {
  if ! [[ -f "${INVOCATION_PATH}/config/.env" ]]; then
    {
      # if this is a release version set RELEASE to 1, add a banner to config/banner and name the banner with the version details
      echo "RELEASE=0"
      echo "EMBA_VERSION=1.5.1"
      echo "CLEANED=0"                                      # used for the final cleaner function for not running it multiple times
      echo "STRICT_MODE=${STRICT_MODE:-0}"
      echo "DEBUG_SCRIPT=${DEBUG_SCRIPT:-0}"
      echo "UPDATE=${UPDATE:-0}"
      echo "ARCH_CHECK=${ARCH_CHECK:-1}"
      echo "RTOS=${RTOS:-1}"                                # Testing RTOS based OS - 1 -> no Linux / 0 -> Linux
      echo "BINARY_EXTENDED=${BINARY_EXTENDED:-0}"
      echo "MAX_EXT_CHECK_BINS=${MAX_EXT_CHECK_BINS:-20}"  
      echo "CONTAINER_EXTRACT=${CONTAINER_EXTRACT:-0}"  
      echo "DISABLE_DEEP=${DISABLE_DEEP:-0}"  
      echo "DEEP_EXT_DEPTH=${DEEP_EXT_DEPTH:-4}"  
      echo "FACT_EXTRACTOR=${FACT_EXTRACTOR:-0}"  
      echo "FIRMWARE=${FIRMWARE:-0}"  
      echo "FORCE=${FORCE:-0}"  
      echo "FORMAT_LOG=${FORMAT_LOG:-0}"  
      echo "HTML=${HTML:-0}"  
      echo "IN_DOCKER=${IN_DOCKER:-0}"
      echo "USE_DOCKER=${USE_DOCKER:-1}"      
      echo "KERNEL=${KERNEL:-0}"  
      echo "KERNEL_CONFIG=${KERNEL_CONFIG:-''}"  
      echo "FIRMWARE_PATH=${FIRMWARE_PATH:-''}"  
      echo "FIRMWARE_PATH1=${FIRMWARE_PATH1:-''}"  
      echo "DIFF_MODE=${DIFF_MODE:-0}"  
      echo "FW_VENDOR=${FW_VENDOR:-''}"  
      echo "FW_VERSION=${FW_VERSION:-''}"  
      echo "FW_DEVICE=${FW_DEVICE:-''}"  
      echo "FW_NOTES=${FW_NOTES:-''}"  
      echo "ARCH=${ARCH:-''}"
      echo "EFI_ARCH=${EFI_ARCH:-''}"
      echo "EXLUDE=${EXLUDE:-()}"
      echo "SELECT_MODULES=${SELECT_MODULES:-()}"
      echo "MODULES_EXPORTED=${MODULES_EXPORTED:-()}"
      echo "MD5_DONE_DEEP=${MD5_DONE_DEEP:-()}"             # for tracking the extracted files in deep extractor
      echo "ROOT_PATH=${ROOT_PATH:-()}"
      echo "FILE_ARR=${FILE_ARR:-()}"
      echo "MAX_MODS=${MAX_MODS:-0}"
      echo "MAX_MOD_THREADS=${MAX_MOD_THREADS:-0}"
      echo "RESTART=${RESTART:-0}"                          # if we find an unfinished EMBA scan we try to only process not finished modules
      echo "FINAL_FW_RM=${FINAL_FW_RM:-0}"                  # remove the firmware working copy after testing (do not waste too much disk space)
      echo "ONLY_DEP=${ONLY_DEP:-0}"                        # test only dependency
      echo "PHP_CHECK=${PHP_CHECK:-1}"
      echo "PRE_CHECK=${PRE_CHECK:-0}"                      # test and extract binary files with binwalk afterwards do a default EMBA scan
      echo "SKIP_PRE_CHECKERS=${SKIP_PRE_CHECKERS:-0}"      # we can set this to 1 to skip all further pre-checkers (WARNING: use this with caution!!!)
      echo "PYTHON_CHECK=${PYTHON_CHECK:-1}"
      # enable L10_DEBUG_MODE in scan profile or default config for further debugging capabilities:
      # * create_emulation_archive for all attempts
      # * do not stop after 2 detected network services
      echo "L10_DEBUG_MODE=${L10_DEBUG_MODE:-0}"
      echo "FULL_EMULATION=${FULL_EMULATION:-0}"            # full system emulation - set it via command line parameter -Q
      echo "QEMULATION=${QEMULATION:-0}"                    # user-mode emulation - set it via command line parameter -E
      # some processes are running long and logging a lot
      # to protect the host we are going to kill them on a QEMU_KILL_SIZE limit
      echo "QEMU_KILL_SIZE=${QEMU_KILL_SIZE:-'10M'}"
      echo "L10_KERNEL_V_LONG=${L10_KERNEL_V_LONG:-'4.1.52'}"
      echo "L10_BB_VER=${L10_BB_VER:-'1.36.1'}"
      # with this variable we can control the behavior of s16 and s120 -> 0 is default an tests only
      # non Linux binaries (binaries not listed in config/linux_common_files.txt. 1 means we test every
      # binary which results in long runtimes
      echo "FULL_TEST=${FULL_TEST:-0}"
      # to get rid of all the running stuff we are going to kill it after RUNTIME
      echo "QRUNTIME=${QRUNTIME:-'20s'}"
      echo "SHELLCHECK=${SHELLCHECK:-1}"
      echo "QUEST_CONTAINER=${QUEST_CONTAINER:-''}"
      echo "GPT_OPTION=${GPT_OPTION:-0}"                    # 0 -> off 1-> unpayed plan 2 -> no rate-limit
      echo "GPT_QUESTION=${GPT_QUESTION:-'For the following code I need you to tell me how an attacker could exploit it and point out all vulnerabilities:'}"
      echo "MINIMUM_GPT_PRIO=${MINIMUM_GPT_PRIO:-1}"        # everything above this value gets checked
      echo "SHORT_PATH=${SHORT_PATH:-0}"                    # short paths in cli output
      echo "THREADED=${THREADED:-1}"                        # 0 -> single thread, 1 -> multi threaded
      echo "YARA=${YARA:-0}"                                # default: disable yara tests
      echo "OVERWRITE_LOG=${OVERWRITE_LOG:-0}"              # automaticially overwrite log directory, if necessary
      echo "MAX_EXT_SPACE=${MAX_EXT_SPACE:-110000}"         # ensure we do not stop on extraction. If you are running into disk space issues you can adjust this variable
      # Important directories
      LOG_DIR="${INVOCATION_PATH}/logs"
      echo "LOG_DIR=${LOG_DIR}"
      # echo "ERROR_LOG=${LOG_DIR}/emba_error.log"
      echo "TMP_DIR=${LOG_DIR}/tmp"
      echo "CSV_DIR=${LOG_DIR}/csv_log"
      echo "JSON_DIR=${LOG_DIR}/json_logs"
      echo "MAIN_LOG_FILE=${MAIN_LOG_FILE:-'emba.log'}"
      CONFIG_DIR="${INVOCATION_PATH}/config"
      echo "CONFIG_DIR=${CONFIG_DIR}"
      EXT_DIR="${INVOCATION_PATH}/external"
      echo "EXT_DIR=${EXT_DIR}"
      HELP_DIR="${INVOCATION_PATH}/helpers"
      echo "HELP_DIR=${HELP_DIR}"
      echo "MOD_DIR=${INVOCATION_PATH:-''}/modules"
      echo "MOD_DIR_LOCAL=${INVOCATION_PATH:-''}/EMBA-Non-free/modules_local"
      echo "PID_LOGGING=${PID_LOGGING:-0}"
      # this will be in TMP_DIR/pid_notes.log
      echo "PID_LOG_FILE=${PID_LOG_FILE:-'pid_notes.log'}"
      echo "BASE_LINUX_FILES=${INVOCATION_PATH:-''}/config/linux_common_files.txt"
      if [[ -f "${CONFIG_DIR}/known_exploited_vulnerabilities.csv" ]]; then
        echo "KNOWN_EXP_CSV=${CONFIG_DIR}/known_exploited_vulnerabilities.csv"
      fi
      if [[ -f "${CONFIG_DIR}/msf_cve-db.txt" ]]; then
        echo "MSF_DB_PATH=${CONFIG_DIR}/msf_cve-db.txt"
      fi
      echo "MSF_INSTALL_PATH=${MSF_INSTALL_PATH:-'/usr/share/metasploit-framework'}"
      if [[ -f "${CONFIG_DIR}/trickest_cve-db.txt" ]]; then
        echo "TRICKEST_DB_PATH=${CONFIG_DIR}/trickest_cve-db.txt"
      fi
      echo "GTFO_CFG=${CONFIG_DIR}/gtfobins_urls.cfg"       # gtfo urls
      echo "SILENT=${SILENT:-0}"
      echo "DISABLE_STATUS_BAR=${DISABLE_STATUS_BAR:-1}"
      # as we encounter issues with the status bar on other system we disable it for non Kali systems
      if [[ -f "/etc/debian_version" ]] && grep -q kali-rolling /etc/debian_version; then
        echo "DISABLE_NOTIFICATIONS=${DISABLE_NOTIFICATIONS:-0}"   # disable notifications and further desktop experience
      else
        echo "DISABLE_NOTIFICATIONS=${DISABLE_NOTIFICATIONS:-1}"   # disable notifications and further desktop experience
      fi
      echo "NOTIFICATION_ID=${NOTIFICATION_ID:-0}"          # initial notification id - needed for notification overlay/replacement
      echo "EMBA_ICON=${HELP_DIR}/emba.svg"
      echo "WSL=${WSL:-0}"                                  # wsl environment detected
      echo "UNBLOB=${UNBLOB:-1}"                            # additional extraction with unblob - https://github.com/onekey-sec/unblob
                                                            # currently the extracted results are not further used. The current implementation
                                                            # is for evaluation purposes
      echo "CVE_BLACKLIST=${CONFIG_DIR}/cve-blacklist.txt"     # include the blacklisted CVE values to this file
      echo "CVE_WHITELIST=${CONFIG_DIR}/cve-whitelist.txt"     # include the whitelisted CVE values to this file
      echo "NVD_DIR=${EXT_DIR}/nvd-json-data-feeds"
      echo "EPSS_DATA_PATH=${EXT_DIR}/EPSS-data/EPSS_CVE_data"
      if [[ -f "${CONFIG_DIR}/module_blacklist.txt" ]]; then
        readarray -t MODULE_BLACKLIST < "${CONFIG_DIR}/module_blacklist.txt"
        echo "MODULE_BLACKLIST=${MODULE_BLACKLIST:-()}"
      fi
      # usually no memory limit is needed, but some modules/tools are wild and we need to protect our system
      echo "TOTAL_MEMORY=$(grep MemTotal /proc/meminfo | awk '{print $2}' || true)"
      echo "Q_MOD_PID=${Q_MOD_PID:-''}"
      echo "UEFI_VERIFIED=${UEFI_VERIFIED:-0}"
      echo "MAIN_CONTAINER=${MAIN_CONTAINER:-''}"
      echo "QUEST_CONTAINER=${QUEST_CONTAINER:-''}"
      echo "DISABLE_DOTS=${DISABLE_DOTS:-0}"                # set to 1 to disable dotting for showing EMBA is alive
      echo "CPE_VERSION=${CPE_VERSION:-'2.3'}"
       # we limit the maximal file log of our SBOM -> change this in the scanning profile
      echo "SBOM_MAX_FILE_LOG=${SBOM_MAX_FILE_LOG:-200}"
      echo "SBOM_MINIMAL=${SBOM_MINIMAL:-0}"
      echo "SBOM_UNTRACKED_FILES=${SBOM_UNTRACKED_FILES:-1}"
      echo "VEX_METRICS=${VEX_METRICS:-1}"
      # usually we test firmware that is already out in the field
      # if this changes this option can be adjusted in the scanning profile
      echo "SBOM_LIFECYCLE_PHASE=${SBOM_LIFECYCLE_PHASE:-'operations'}"
      # we can enable/disable the s08 submodules with the following array configuration
      # -> just comment the submodule that should not be used
      # usually this should be done via a scan-profile
      S08_MODULES_ARR=( "S08_submodule_debian_pkg_mgmt_parser" )
      S08_MODULES_ARR+=( "S08_submodule_deb_package_parser" )
      S08_MODULES_ARR+=( "S08_submodule_openwrt_pkg_mgmt_parser" )
      S08_MODULES_ARR+=( "S08_submodule_openwrt_ipk_package_parser" )
      S08_MODULES_ARR+=( "S08_submodule_rpm_pkg_mgmt_parser" )
      S08_MODULES_ARR+=( "S08_submodule_rpm_package_parser" )
      S08_MODULES_ARR+=( "S08_submodule_bsd_package_parser" )
      S08_MODULES_ARR+=( "S08_submodule_python_pip_package_mgmt_parser" )
      S08_MODULES_ARR+=( "S08_submodule_python_requirements_parser" )
      S08_MODULES_ARR+=( "S08_submodule_python_poetry_lock_parser" )
      S08_MODULES_ARR+=( "S08_submodule_java_archives_parser" )
      S08_MODULES_ARR+=( "S08_submodule_ruby_gem_archive_parser" )
      S08_MODULES_ARR+=( "S08_submodule_alpine_apk_package_parser" )
      S08_MODULES_ARR+=( "S08_submodule_windows_exifparser" )
      S08_MODULES_ARR+=( "S08_submodule_rust_cargo_lock_parser" )
      S08_MODULES_ARR+=( "S08_submodule_node_js_package_lock_parser" )
      S08_MODULES_ARR+=( "S08_submodule_c_conanfile_txt_parser" )
      echo "S08_MODULES_ARR=(${S08_MODULES_ARR[@]})"
    } > "${INVOCATION_PATH}/config/.env" 2>/dev/null         # store that into env file
  else
    print_output "[DEBUG] env already set" # TODO this is an error state make it print proper
  fi
  # read and export all vars in .env
  if [[ ! -f "${INVOCATION_PATH}/config/.env" ]]; then
    export "$(grep -v '^#' .env | xargs)"
  fi
}

set_log_paths() {
  export SBOM_LOG_PATH="${LOG_DIR}/SBOM"
  export P02_CSV_LOG="${CSV_DIR}/p02_firmware_bin_file_check.csv"
  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  export P55_LOG="${LOG_DIR}/p55_unblob_extractor.txt"
  export P60_LOG="${LOG_DIR}/p60_deep_extractor.txt"
  export P99_LOG="${LOG_DIR}/p99_prepare_analyzer.txt"
  export P35_LOG="${LOG_DIR}/p35_uefi_extractor.txt"
  export S02_LOG="${LOG_DIR}/s02_uefi_fwhunt.txt"
  export S02_CSV_LOG="${CSV_DIR}/s02_uefi_fwhunt.csv"
  export S03_LOG="${LOG_DIR}/s03_firmware_bin_base_analyzer.txt"
  export S05_LOG="${LOG_DIR}/s05_firmware_details.txt"
  export S06_LOG="${LOG_DIR}/s06_distribution_identification.txt"
  export S06_CSV_LOG="${CSV_DIR}/s06_distribution_identification.csv"
  export S08_CSV_LOG="${CSV_DIR}/s08_package_mgmt_extractor.csv"
  export S09_CSV_LOG="${CSV_DIR}/s09_firmware_base_version_check.csv"
  export S12_LOG="${LOG_DIR}/s12_binary_protection.txt"
  export S12_CSV_LOG="${CSV_DIR}/s12_binary_protection.csv"
  export S13_LOG="${LOG_DIR}/s13_weak_func_check.txt"
  export S13_CSV_LOG="${CSV_DIR}/s13_weak_func_check.csv"
  export S14_LOG="${LOG_DIR}/s14_weak_func_radare_check.txt"
  export S14_CSV_LOG="${CSV_DIR}/s14_weak_func_radare_check.csv"
  export S16_LOG="${LOG_DIR}/s16_ghidra_decompile_checks.txt"
  export S17_LOG="${LOG_DIR}/s17_cwe_checker.txt"
  export S17_CSV_LOG="${CSV_DIR}/s17_apk_check.csv"
  export S25_CSV_LOG="${CSV_DIR}/s25_kernel_check.csv"
  export S20_LOG="${LOG_DIR}/s20_shell_check.txt"
  export S21_LOG="${LOG_DIR}/s21_python_check.txt"
  export S22_LOG="${LOG_DIR}/s22_php_check.txt"
  export S22_CSV_LOG="${CSV_DIR}/s22_php_check.csv"
  export S23_LOG="${LOG_DIR}/s23_lua_check.txt"
  export S23_CSV_LOG="${CSV_DIR}/s23_lua_check.csv"
  export S24_LOG="${LOG_DIR}/s24_kernel_bin_identifier.txt"
  export S24_CSV_LOG="${CSV_DIR}/s24_kernel_bin_identifier.csv"
  export S25_LOG="${LOG_DIR}/s25_kernel_check.txt"
  export S26_LOG="${LOG_DIR}/s26_kernel_vuln_verifier.txt"
  export S26_LOG_DIR="${S26_LOG/\.txt/\/}"
  export S30_LOG="${LOG_DIR}/s30_version_vulnerability_check.txt"
  export S36_LOG="${LOG_DIR}/s36_lighttpd.txt"
  export S36_LOG_DIR="${S36_LOG/\.txt/\/}"
  export S36_CSV_LOG="${CSV_DIR}/s36_lighttpd.csv"
  export S40_LOG="${LOG_DIR}/s40_weak_perm_check.txt"
  export S45_LOG="${LOG_DIR}/s45_pass_file_check.txt"
  export S50_LOG="${LOG_DIR}/s50_authentication_check.txt"
  export S55_LOG="${LOG_DIR}/s55_history_file_check.txt"
  export S60_LOG="${LOG_DIR}/s60_cert_file_check.txt"
  export S85_LOG="${LOG_DIR}/s85_ssh_check.txt"
  export S95_LOG="${LOG_DIR}/s95_interesting_files_check.txt"
  export S107_LOG="${LOG_DIR}/s107_deep_password_search.txt"
  export S108_LOG="${LOG_DIR}/s108_stacs_password_search.txt"
  export S108_CSV_LOG="${CSV_DIR}/s108_stacs_password_search.csv"
  export S109_LOG="${LOG_DIR}/s109_jtr_local_pw_cracking.txt"
  export S110_LOG="${LOG_DIR}/s110_yara_check.txt"
  export S116_CSV_LOG="${CSV_DIR}/s116_qemu_version_detection.csv"
  export S118_CSV_LOG="${CSV_DIR}/s118_busybox_verifier.csv"
  export S118_LOG="${LOG_DIR}/s118_busybox_verifier.txt"
  export S118_LOG_DIR="${S118_LOG/\.txt/\/}"
  export Q02_LOG="${LOG_DIR}/q02_openai_question.txt"
  export L10_LOG="${LOG_DIR}/l10_system_emulator.txt"
  export L10_SYS_EMU_RESULTS="${LOG_DIR}/emulator_online_results.log"
  export L15_LOG="${LOG_DIR}/l15_emulated_checks_init.txt"
  export L15_CSV_LOG="${CSV_DIR}/l15_emulated_checks_nmap.csv"
  export L20_LOG="${LOG_DIR}/l20_snmp_checks.txt"
  export L25_LOG="${LOG_DIR}/l25_web_checks.txt"
  export L25_CSV_LOG="${CSV_DIR}/l25_web_checks.csv"
  export L35_CSV_LOG="${CSV_DIR}/l35_metasploit_check.csv"
  export F15_LOG="${LOG_DIR}/f15_cyclonedx_sbom.txt"
  export F15_CSV_LOG="${CSV_DIR}/f15_cyclonedx_sbom.csv"
  export F17_LOG_DIR="${LOG_DIR}/f17_cve_bin_tool"
  export F50_CSV_LOG="${CSV_DIR}/f50_base_aggregator.csv"
}

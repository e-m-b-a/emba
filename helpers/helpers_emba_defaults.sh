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

# Description: Sets default values for EMBA


set_defaults() {
  # if this is a release version set RELEASE to 1, add a banner to config/banner and name the banner with the version details
  export RELEASE=1
  export EMBA_VERSION="1.5.2"

  export CLEANED=0              # used for the final cleaner function for not running it multiple times
  export STRICT_MODE=0
  export DEBUG_SCRIPT=0
  export UPDATE=0
  export ARCH_CHECK=1
  export RTOS=1                 # Testing RTOS based OS - 1 -> no Linux / 0 -> Linux
  export BINARY_EXTENDED=0
  export MAX_EXT_CHECK_BINS=20
  export CONTAINER_EXTRACT=0
  export DISABLE_DEEP=0
  export DEEP_EXTRACTOR="unblob"  # binwalk/unblob
  export DEEP_EXT_DEPTH=4
  export FACT_EXTRACTOR=0
  export FIRMWARE=0
  export FORCE=0
  export FORMAT_LOG=0
  export HTML=0
  export IN_DOCKER=0
  export USE_DOCKER=1
  export KERNEL=0
  export KERNEL_CONFIG=""
  export FIRMWARE_PATH=""
  export FIRMWARE_PATH1=""
  export DIFF_MODE=0
  export FW_VENDOR=""
  export FW_VERSION=""
  export FW_DEVICE=""
  export FW_NOTES=""
  export ARCH=""
  export EFI_ARCH=""
  export EXCLUDE=()
  export SELECT_MODULES=()
  export MODULES_EXPORTED=()
  export MD5_DONE_DEEP=()       # for tracking the extracted files in deep extractor
  export ROOT_PATH=()
  export FILE_ARR=()
  export MAX_MODS=0
  export MAX_MOD_THREADS=0
  export RESTART=0              # if we find an unfinished EMBA scan we try to only process not finished modules
  export FINAL_FW_RM=0          # remove the firmware working copy after testing (do not waste too much disk space)
  export ONLY_DEP=0             # test only dependency
  export RESCAN_SBOM=0          # rescan existing log directory with F17 module only
  export PHP_CHECK=1
  export PRE_CHECK=0            # test and extract binary files with binwalk
                                # afterwards do a default EMBA scan
  export SKIP_PRE_CHECKERS=0    # we can set this to 1 to skip all further pre-checkers (WARNING: use this with caution!!!)
  export PYTHON_CHECK=1
  # enable L10_DEBUG_MODE in scan profile or default config for further debugging capabilities:
  # * create_emulation_archive for all attempts
  # * do not stop after 2 detected network services
  export L10_DEBUG_MODE=0
  export FULL_EMULATION=0       # full system emulation - set it via command line parameter -Q
  export QEMULATION=0           # user-mode emulation - set it via command line parameter -E
  # some processes are running long and logging a lot
  # to protect the host we are going to kill them on a QEMU_KILL_SIZE limit
  export QEMU_KILL_SIZE="10M"
  export L10_KERNEL_V_LONG="4.14.336"
  export L10_BB_VER="1.36.1"
  export MAX_SYSTEM_RESTART_CNT=20  # how often we try to restart the system if it is not available anymore
  export FULL_TEST=0            # with this variable we can control the behavior of s16 and s120 -> 0 is default an tests only
                                # non Linux binaries (binaries not listed in config/linux_common_files.txt. 1 means we test every
                                # binary which results in long runtimes
  # to get rid of all the running stuff we are going to kill it after RUNTIME
  export QRUNTIME="20s"

  export SHELLCHECK=1

  export GPT_OPTION=0           # 0 -> off 1-> unpayed plan 2 -> no rate-limit
  export GPT_QUESTION="For the following code I need you to tell me how an attacker could exploit it and point out all vulnerabilities:"
  export MINIMUM_GPT_PRIO=1     # everything above this value gets checked

  export SHORT_PATH=0           # short paths in cli output
  export THREADED=1             # 0 -> single thread
                                # 1 -> multi threaded
  export YARA=0                 # default: disable yara tests
  export OVERWRITE_LOG=0        # automatically overwrite log directory, if necessary
  export MAX_EXT_SPACE=110000   # ensure we do not stop on extraction. If you are running into disk space issues you can adjust this variable
  export LOG_DIR="${INVOCATION_PATH}""/logs"
  # export ERROR_LOG="${LOG_DIR}/emba_error.log"  # This variable is reserved for logging errors. It is currently disabled but can be enabled for debugging purposes in the future.
  export TMP_DIR="${LOG_DIR}/tmp"
  export CSV_DIR="${LOG_DIR}/csv_logs"
  export JSON_DIR="${LOG_DIR}/json_logs"
  export MAIN_LOG_FILE="emba.log"
  export CONFIG_DIR="${INVOCATION_PATH}/config"
  export EXT_DIR="${INVOCATION_PATH}/external"
  export HELP_DIR="${INVOCATION_PATH}/helpers"
  export MOD_DIR="${INVOCATION_PATH}/modules"
  export MOD_DIR_LOCAL="${INVOCATION_PATH}/EMBA-Non-free/modules_local"
  export PID_LOGGING=0
  # this will be in TMP_DIR/pid_notes.log
  export PID_LOG_FILE="pid_notes.log"
  export BASE_LINUX_FILES="${CONFIG_DIR}/linux_common_files.txt"
  if [[ -f "${CONFIG_DIR}"/known_exploited_vulnerabilities.csv ]]; then
    export KNOWN_EXP_CSV="${CONFIG_DIR}/known_exploited_vulnerabilities.csv"
  fi
  if [[ -f "${CONFIG_DIR}"/msf_cve-db.txt ]]; then
    export MSF_DB_PATH="${CONFIG_DIR}/msf_cve-db.txt"
  fi
  export MSF_INSTALL_PATH="/usr/share/metasploit-framework"
  if [[ -f "${CONFIG_DIR}/trickest_cve-db.txt" ]]; then
    export TRICKEST_DB_PATH="${CONFIG_DIR}/trickest_cve-db.txt"
  fi
  export GTFO_CFG="${CONFIG_DIR}/gtfobins_urls.cfg"         # gtfo urls
  export SILENT=0
  export DISABLE_STATUS_BAR=1
  # as we encounter issues with the status bar on other system we disable it for non Kali systems
  export DISABLE_NOTIFICATIONS=1    # disable notifications and further desktop experience
  if [[ -f "/etc/debian_version" ]] && grep -q kali-rolling /etc/debian_version; then
    export DISABLE_NOTIFICATIONS=0    # disable notifications and further desktop experience
  fi
  export NOTIFICATION_ID=0          # initial notification id - needed for notification overlay/replacement
  export EMBA_ICON=""
  EMBA_ICON=$(realpath "${HELP_DIR}"/emba.svg)
  export WSL=0    # wsl environment detected
  export UNBLOB=1 # additional extraction with unblob - https://github.com/onekey-sec/unblob
  export CVE_BLACKLIST="${CONFIG_DIR}"/cve-blacklist.txt  # include the blacklisted CVE values to this file
  export CVE_WHITELIST="${CONFIG_DIR}"/cve-whitelist.txt  # include the whitelisted CVE values to this file
  export NVD_DIR="${EXT_DIR}"/nvd-json-data-feeds
  export EPSS_DATA_PATH="${EXT_DIR}"/EPSS-data/EPSS_CVE_data

  export MODULE_BLACKLIST=()
  if [[ -f "${CONFIG_DIR}"/module_blacklist.txt ]]; then
    readarray -t MODULE_BLACKLIST < "${CONFIG_DIR}"/module_blacklist.txt
  fi
  # usually no memory limit is needed, but some modules/tools are wild and we need to protect our system
  export TOTAL_MEMORY=0
  TOTAL_MEMORY="$(grep MemTotal /proc/meminfo | awk '{print $2}' || true)"
  export Q_MOD_PID=""
  export UEFI_VERIFIED=0
  export MAIN_CONTAINER=""
  export QUEST_CONTAINER=""
  export DISABLE_DOTS=0     # set to 1 to disable dotting for showing EMBA is alive
  export CPE_VERSION="2.3"

  # we limit the maximal file log of our SBOM -> change this in the scanning profile
  export SBOM_MAX_FILE_LOG=200
  export SBOM_MINIMAL=0
  export SBOM_UNTRACKED_FILES=1
  export VEX_METRICS=1
  # usually we test firmware that is already out in the field
  # if this changes this option can be adjusted in the scanning profile
  export SBOM_LIFECYCLE_PHASE="operations"

  # we can enable/disable the s08 submodules with the following array configuration
  # -> just comment the submodule that should not be used
  # usually this should be done via a scan-profile
  export S08_MODULES_ARR=()
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
  S08_MODULES_ARR+=( "S08_submodule_perl_cpan_parser" )
  S08_MODULES_ARR+=( "S08_submodule_php_composer_lock" )
  S08_MODULES_ARR+=( "S08_submodule_python_pipfile_lock" )
  S08_MODULES_ARR+=( "S08_submodule_apk_pkg_mgmt_parser" )
}

set_log_paths() {
  export SBOM_LOG_PATH="${LOG_DIR}/SBOM"
  export EMBA_SBOM_JSON="${SBOM_LOG_PATH}/EMBA_cyclonedx_sbom.json"
  export P02_LOG="${LOG_DIR}/p02_firmware_bin_file_check.txt"
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
  export S09_LOG="${LOG_DIR}/s09_firmware_base_version_check.txt"
  export S09_LOG_DIR="${S09_LOG/\.txt/\/}"
  export S12_LOG="${LOG_DIR}/s12_binary_protection.txt"
  export S12_CSV_LOG="${CSV_DIR}/s12_binary_protection.csv"
  export S13_LOG="${LOG_DIR}/s13_weak_func_check.txt"
  export S13_CSV_LOG="${CSV_DIR}/s13_weak_func_check.csv"
  export S14_LOG="${LOG_DIR}/s14_weak_func_radare_check.txt"
  export S14_CSV_LOG="${CSV_DIR}/s14_weak_func_radare_check.csv"
  export S15_CSV_LOG="${CSV_DIR}/s15_radare_decompile_checks.csv"
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

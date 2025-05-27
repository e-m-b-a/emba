#!/bin/bash
# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Thomas Gingele <b1tc0r3@proton.me>
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Thomas Gingele
#
# Description:  This is an experimental EMBA module. It is designed to run user-defined python
#               scripts during the analysis.
#

S28_python_run() {
    module_log_init "${FUNCNAME[0]}"
    module_title "Python Runner"
    pre_module_reporter "${FUNCNAME[0]}"

    local lSCRIPT_DIR="${MOD_DIR}/${FUNCNAME[0]}"
    local lPYTHON_SCRIPT_COUNT=${#PYTHON_SCRIPTS[@]}
    local lCOUNT_SUBMODULE_FINDINGS=0
    local lCOUNT_TOTAL_FINDINGS=0
    local lSCRIPT=""

    if [[ ${lPYTHON_SCRIPT_COUNT} -gt 0 ]]; then
        print_output "[*] ${lPYTHON_SCRIPT_COUNT} Python script/s queued for execution."

        for lSCRIPT in "${PYTHON_SCRIPTS[@]}"; do
            sub_module_title "Execution of Python runner for ${ORANGE}${lSCRIPT}${NC}"
            print_output "[*] Executing: ${ORANGE}${lSCRIPT_DIR}/${lSCRIPT}.py${NC}"

            lCOUNT_SUBMODULE_FINDINGS=$(python3 "${lSCRIPT_DIR}/${lSCRIPT}.py" | grep "FINDINGS" | sed "s/FINDINGS://")
            lCOUNT_TOTAL_FINDINGS=$((lCOUNT_TOTAL_FINDINGS + lCOUNT_SUBMODULE_FINDINGS))

            cat "${LOG_PATH_MODULE}/${lSCRIPT}.txt" >> "${LOG_FILE}"
            print_output "[*] Python module ${ORANGE}${lSCRIPT}${NC} reported a total of ${ORANGE}${lCOUNT_SUBMODULE_FINDINGS}${NC} findings."
        done

    else
        print_output "[*] No Python scripts queued for execution."
    fi

    sub_module_title "Final results for ${FUNCNAME[0]}"
    print_output "Total results count: ${lCOUNT_TOTAL_FINDINGS}"
    module_end_log "${FUNCNAME[0]}" "${lCOUNT_TOTAL_FINDINGS}"
}

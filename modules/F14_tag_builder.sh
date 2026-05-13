#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# The documentation can be generated with the following command:
# perl -ne "s/^\t+//; print if m/END_OF_DOCS'?\$/ .. m/^\s*'?END_OF_DOCS'?\$/ and not m/END_OF_DOCS'?$/;" modules/F14_tag_builder.sh
# or with pod2text modules/F14_tag_builder.sh
: <<'END_OF_DOCS'
=pod

=encoding UTF-8

=head1 F14_tag_builder

=head2 F14_tag_builder Short description

This module collects results from multiple (S-, L-, and P-phase) modules and builds a unified tag file in JSON format.

=head2 F14_tag_builder Detailed description

F14_tag_builder aggregates findings from modules and generates tags.
It extracts key metadata such as firmware vendor, detected CPU architecture, scripting languages
(PHP, Python, Lua), operating system (Linux), password-cracking results, and emulation/exploitation
outcomes. The collected tags are deduplicated, sorted, and written to a JSON file (LOG_PATH_MODULE/tags.json)
with jo.

The following tags can be generated:

=over 4

=item * EMBA - Base tag, always included

=item * Vendor name - From FW_VENDOR variable if detected

=item * CPU architecture - From P99 file-type identification statistics

=item * PHP - From S22 PHP analysis

=item * Python - From S21 Python analysis

=item * LUA - From S23 LUA analysis

=item * Linux - From S03 OS detection, S25 kernel version analysis, or os_detector helper

=item * cracked - From S109 password/credential cracking

=item * emulated - From L10 emulation results

=item * exploited - From L35 exploitation results

=back

If a module has not run before, it is silently skipped.
However, the "emba"-tag is always included and thus the output is never empty

=head2 F14_tag_builder 3rd party tools

jo - JSON output tool to create the tags.json output file

=head2 F14_tag_builder Testfirmware

Any firmware image that produces results in the prerequisite modules (see Detailed description)

=head2 F14_tag_builder Output

Example output:
{
  "tags": [
    "ARM",
    "EMBA",
    "Linux",
    "Python",
    "cracked",
    "emulated",
    "exploited"
  ]
}

=head2 F14_tag_builder License

EMBA module F14_tag_builder is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only
Link to license document: https://github.com/e-m-b-a/emba/blob/master/LICENSE

=head2 F14_tag_builder Todo

None

=head2 F14_tag_builder Known issues

None

=head2 F14_tag_builder Author(s)

Michael Messner

=cut

END_OF_DOCS

F14_tag_builder() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final Tag builder"
  pre_module_reporter "${FUNCNAME[0]}"

  local lTAGs_ARR=("EMBA")
  local lTAG=""
  local lARCH=""

  if [[ -n "${FW_VENDOR}" ]]; then
    lTAGs_ARR+=("${FW_VENDOR}")
  fi

  # architecture
  if [[ -f "${P99_LOG}" ]]; then
    lARCH="$(grep -a "\[\*\]\ Statistics:" "${P99_LOG}" | cut -d: -f2 | grep -v "NA" || true)"
    if [[ -n "${lARCH}" ]]; then
      lTAGs_ARR+=("${lARCH}")
    fi
  fi

  # scripting languages
  if [[ -f "${S22_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S22_LOG}" | cut -d: -f2 || true) -gt 0 ]] ||
      [[ $(grep -a "\[\*\]\ Statistics1:" "${S22_LOG}" | cut -d: -f2 || true) -gt 0 ]]; then
      lTAGs_ARR+=("PHP")
    fi
  fi
  if [[ -f "${S21_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S21_LOG}" | cut -d: -f2 || true) -gt 0 ]]; then
      lTAGs_ARR+=("Python")
    fi
  fi
  if [[ -f "${S23_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S23_LOG}" | cut -d: -f3 || true) -gt 0 ]]; then
      lTAGs_ARR+=("LUA")
    fi
  fi

  # OS detection
  if [[ -f "${S03_LOG}" ]]; then
    if [[ $(grep -a -c "verified Linux" "${S03_LOG}" || true) -gt 0 ]]; then
      lTAGs_ARR+=("Linux")
    fi
  fi
  if [[ -f "${S25_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S25_LOG}" | cut -d: -f2 || true) =~ [0-9]+\.[0-9]+(\.[0-9]+)+? ]]; then
      lTAGs_ARR+=("Linux")
    fi
  fi
  if os_detector | grep -q "verified.*Linux"; then
    lTAGs_ARR+=("Linux")
  fi

  # other module tags like passwords cracked
  if [[ -f "${S109_LOG}" ]]; then
    if [[ $(grep -a "\[\*\]\ Statistics:" "${S109_LOG}" | cut -d: -f2 || true) -gt 0 ]]; then
      lTAGs_ARR+=("cracked")
    fi
  fi

  # emulation
  if [[ -f "${L10_SYS_EMU_RESULTS}" ]]; then
    if [[ $(grep -c "TCP ok;" "${L10_SYS_EMU_RESULTS}" || true) -gt 0 ]]; then
      lTAGs_ARR+=("emulated")
    fi
  fi
  if [[ -f "${L35_CSV_LOG}" ]]; then
    if [[ $(grep -v -c "Source" "${L35_CSV_LOG}" || true) -gt 0 ]]; then
      lTAGs_ARR+=("exploited")
    fi
  fi

  mapfile -t lTAGs_ARR < <(printf "%s\n" "${lTAGs_ARR[@]}" | sort -u)

  jo -p "tags=$(jo -a "${lTAGs_ARR[@]}")" >"${LOG_PATH_MODULE}"/tags.json
  if [[ -f "${LOG_PATH_MODULE}"/tags.json ]]; then
    print_ln
    print_output "[*] Generated tags:" "" "${LOG_PATH_MODULE}"/tags.json
    for lTAG in "${lTAGs_ARR[@]}"; do
      print_output "$(indent "$(orange "${lTAG}")")"
    done
    print_ln
  fi

  module_end_log "${FUNCNAME[0]}" "${#lTAGs_ARR[@]}"
}

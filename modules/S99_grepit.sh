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
# The original code (from line 187 till the end of the file) from the CRASS project is licensed the following way:
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <floyd at floyd dot ch> wrote this file. As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return
# floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
# July 2013
# ----------------------------------------------------------------------------
#
# Original Author: Floyd - https://github.com/floyd-fuh
# EMBA Author(s): Michael Messner, Pascal Eckmann

# Description:  Initial implementation of the great grepit tool from CRASS (code review audit script scanner)
#               CRASS: https://github.com/floyd-fuh/crass/
#               Grepit: https://github.com/floyd-fuh/crass/blob/master/grep-it.sh
#               Original grepit description:
#               A simple greper for code, loot, IT-tech-stuff-the-customer-throws-at-you.
#               Tries to find IT security and privacy related stuff.

# shellcheck disable=SC2016

S99_grepit() {

  module_log_init "${FUNCNAME[0]}"

  if [[ "${QUICK_SCAN:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_title "Intelligent grepit module"
  print_output "Running intelligent grepit module for identification of interesting spots within the firmware ..." "no_log"

  pre_module_reporter "${FUNCNAME[0]}"

  local lWAIT_PIDS_S99_ARR=()
  local lGREPIT_MODULES_ARR=()
  local lGREPIT_RESULTS=0

  local lMAX_MOD_THREADS=1
  local lMEM_LIMIT=$(( "${TOTAL_MEMORY}"/3 ))


  # grepit options:
  # Sometimes we look for composite words with wildcard, eg. root.{0,20}detection, this is the maximum
  # of random characters that can be in between. The higher the value the more strings will potentially be flagged.
  export WILDCARD_SHORT=20
  export WILDCARD_LONG=200
  # Weird grep behaviour with clearing to the end of line -.-
  # This variable prevents this behaviour
  export GREP_COLORS=ne
  # sometimes we have so many results. We need to limit it a bit
  # -m is limit per file and in this case per grep search per file
  local lLIMIT_GREP=(-m 100)
  # Do not remove -rP if you don't know what you are doing, otherwise you probably break this script
  local lGREP_ARGUMENTS=(-a -n -A 1 -B 3 -rP)
  # Open the colored outputs with "less -R" or cat, otherwise remove --color=always (not recommended, colors help to find the matches in huge text files)
  local lCOLOR_ARGUMENTS=("--color=always")
  export STANDARD_GREP_ARGUMENTS=("${lGREP_ARGUMENTS[@]}" "${lCOLOR_ARGUMENTS[@]}" "${lLIMIT_GREP[@]}")
  export ENABLE_LEAST_LIKELY=0

  mapfile -t lGREPIT_MODULES_ARR < <(grep -E "^grepit_module.*\(\) " "${MOD_DIR}"/"${FUNCNAME[0]}".sh | sed -e 's/()\ .*//g' | sort -u)
  print_output "[*] Loaded ${ORANGE}${#lGREPIT_MODULES_ARR[@]}${NC} grepit modules\n"

  write_csv_log "Grepit test" "Number of results" "Used args for grep" "Regex used" "Grepit comment"

  if [[ ${THREADED} -eq 1 ]]; then
    for GREPIT_MODULE in "${lGREPIT_MODULES_ARR[@]}"; do
      "${GREPIT_MODULE}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_S99_ARR+=( "${lTMP_PID}" )
      store_kill_pids "${lTMP_PID}"
      max_pids_protection "${lMAX_MOD_THREADS}" lWAIT_PIDS_S99_ARR
    done
  else
    for GREPIT_MODULE in "${lGREPIT_MODULES_ARR[@]}"; do
      "${GREPIT_MODULE}"
    done
  fi

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S99_ARR[@]}"

  grepit_reporter

  lGREPIT_RESULTS=$(grep -v -c -E "\ Searching\ \(" "${LOG_PATH_MODULE}"/[0-9]_* | cut -d: -f2 | paste -sd+ | bc || true)
  print_output "\n"
  print_output "[*] Found ${ORANGE}${lGREPIT_RESULTS}${NC} results via grepit."

  module_end_log "${FUNCNAME[0]}" "${lGREPIT_RESULTS}"
}

grepit_reporter() {
  local lCSV_LOG=""
  lCSV_LOG="${LOG_FILE_NAME/\.txt/\.csv}"
  lCSV_LOG="${CSV_DIR}""/""${lCSV_LOG}"
  local lGREPIT_RESULTS_DETAILS_ARR=()
  local lRESULT=""
  local lCURRENT_TEST=""
  local lLINES_OF_OUTPUT=""
  local lCOMMENT=""
  local lOUTFILE=""

  if [[ -f "${lCSV_LOG}" ]]; then
    readarray -t lGREPIT_RESULTS_DETAILS_ARR < <(cut -d\; -f1,2,5 "${lCSV_LOG}" | grep -v "Grepit test" | grep -v "^$" | sort -u)
    for lRESULT in "${lGREPIT_RESULTS_DETAILS_ARR[@]}"; do
      lCURRENT_TEST=$(echo "${lRESULT}" | cut -d\; -f1)
      lLINES_OF_OUTPUT=$(echo "${lRESULT}" | cut -d\; -f2)
      lCOMMENT=$(echo "${lRESULT}" | cut -d\; -f3)
      lOUTFILE="${lCURRENT_TEST}".txt

      print_output "[*] ${ORANGE}${lLINES_OF_OUTPUT}${NC} results of grepit module ${ORANGE}${lCURRENT_TEST}${NC} (${ORANGE}${lCOMMENT}${NC})." "" "${LOG_PATH_MODULE}/${lOUTFILE}"
    done
  fi
}

grepit_search() {
  local lLINES_OF_OUTPUT=0
  local lGREP_COMMAND="grep"
  local lLOG_DETAILS=1
  local lCOMMENT="${1:-NA}"
  local lEXAMPLE="${2:-NA}"
  local lFALSE_POSITIVES_EXAMPLE="${3:-NA}"
  local lSEARCH_REGEX="${4}"
  local lOUTFILE="${5:-MISSING_LOG_DIR.txt}"
  local lCURRENT_TEST=""
  if [[ -v 6 ]]; then
    local lARGS_FOR_GREP_ARR=("${6}") # usually just -i for case insensitive or empty, very rare we use -o for match-only part with no context info
  else
    local lARGS_FOR_GREP_ARR=()
  fi

  if [[ "${ENABLE_LEAST_LIKELY}" -eq 0 ]] && [[ "${lOUTFILE}" == 9_* ]]; then
    print_output "[-] Skipping searching for ${lOUTFILE} with regex ${lSEARCH_REGEX}. Set ENABLE_LEAST_LIKELY in the module options to 1 if you would like to." "no_log"
  else
    write_log "[*] Searching (args for grep: ${ORANGE}${lARGS_FOR_GREP_ARR[*]}${NC}) for ${ORANGE}${lSEARCH_REGEX}${NC}." "${LOG_PATH_MODULE}/${lOUTFILE}"

    if [[ "${lLOG_DETAILS}" -eq 1 ]]; then
      write_log "[*] Grepit state info - comment: ${ORANGE}${lCOMMENT}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Filename ${ORANGE}${lOUTFILE}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Example: ${ORANGE}${lEXAMPLE}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - False positive example: ${ORANGE}${lFALSE_POSITIVES_EXAMPLE}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Grep args: ${ORANGE}${lARGS_FOR_GREP_ARR[*]}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "[*] Grepit state info - Search regex: ${ORANGE}${lSEARCH_REGEX}${NC}" "${LOG_PATH_MODULE}/${lOUTFILE}"
      write_log "" "${LOG_PATH_MODULE}/${lOUTFILE}"
    fi

    ulimit -Sv "${lMEM_LIMIT}"
    "${lGREP_COMMAND}" "${lARGS_FOR_GREP_ARR[@]}" "${STANDARD_GREP_ARGUMENTS[@]}" -- "${lSEARCH_REGEX}" "${FIRMWARE_PATH}" |& safe_logging "${LOG_PATH_MODULE}/${lOUTFILE}" 0 || true
    ulimit -Sv unlimited

    if [[ "${lLOG_DETAILS}" -eq 1 ]]; then
      if [[ -f "${LOG_PATH_MODULE}/${lOUTFILE}" ]] && ! [[ $(grep -v -c -E "\ Searching\ \(" "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null) -gt 7 ]]; then
        rm "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null
      fi
    else
      if [[ -f "${LOG_PATH_MODULE}/${lOUTFILE}" ]] && ! [[ $(grep -v -c -E "\ Searching\ \(" "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null) -gt 0 ]]; then
        rm "${LOG_PATH_MODULE}/${lOUTFILE}" 2>/dev/null
      fi
    fi
    if [[ -f "${LOG_PATH_MODULE}/${lOUTFILE}" ]]; then
      if [[ "${lLOG_DETAILS}" -eq 1 ]]; then
        lLINES_OF_OUTPUT=$(( "$(wc -l < "${LOG_PATH_MODULE}/${lOUTFILE}")" -8 ))
      else
        lLINES_OF_OUTPUT=$(( "$(wc -l < "${LOG_PATH_MODULE}/${lOUTFILE}")" -1 ))
      fi
      lCURRENT_TEST=$(basename -s .txt "${lOUTFILE}")
      # this is the output to the terminal. For the final report we wait till all tests are finished and then we
      # parse the csv output file and sort it according the test priority - 1-9, where 1 is more interesting
      # (low false positive rate, certainty of "vulnerability") and 9 is only "you might want to have a look when you are desperately looking for vulns")
      print_output "[*] ${ORANGE}${lLINES_OF_OUTPUT}${NC} results of grepit module ${ORANGE}${lCURRENT_TEST}${NC}." "no_log"
      write_csv_log "${lCURRENT_TEST}" "${lLINES_OF_OUTPUT}" "${lARGS_FOR_GREP_ARR[*]}" "${lSEARCH_REGEX}" "${lCOMMENT}"
    fi
  fi
}

# The following code is 1 by 1 copy of the original source from here:
# https://github.com/floyd-fuh/crass/blob/f2da104b073f530fbadeda7578c39a377ebd296b/grep-it.sh#L307
# We have only moved every checker area to its own function
# Todo: Move this to a module helper file
grepit_module_java() {
  print_output "[*] Starting Grepit Java module" "no_log"

  grepit_search "All Strings between double quotes. Like the command line tool 'strings' for Java code, but only catches direct declaration and initialization, because otherwise this regex would take forever." \
  'String bla = "This is a Java String";' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'String\s[a-zA-Z_$]{1,1}[a-zA-Z0-9_$]{0,25}\s?=\s?"[^"]{4,500}"' \
  "9_java_strings.txt" \
  "-o" #Special case, we only want to show the strings themselves, therefore -o to output the match only

  grepit_search "All javax.crypto usage" \
  'import javax.crypto.bla;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'javax.crypto' \
  "8_java_crypto_javax-crypto.txt"

  grepit_search "Bouncycastle is a common Java crypto provider" \
  'import org.bouncycastle.bla;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "bouncy.{0,${WILDCARD_SHORT}}}castle" \
  "8_java_crypto_bouncycastle.txt" \
  "-i"

  grepit_search "SecretKeySpec is used to initialize a new encryption key: instance of SecretKey, often passed in the first argument as a byte[], which is the actual key" \
  'new SecretKeySpec(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'new\sSecretKeySpec\(' \
  "2_java_crypto_new-SecretKeySpec.txt" \
  "-i"

  grepit_search "PBEKeySpec(\" is used to initialize a new encryption key: instance of PBEKeySpec, often passed in the first argument as a byte[] like \"foobar\".getBytes(), which is the actual key. I leave this here for your amusement: https://github.com/wso2/wso2-synapse/blob/master/modules/securevault/src/main/java/org/apache/synapse/securevault/secret/handler/JBossEncryptionSecretCallbackHandler.java#L40 " \
  'new PBEKeySpec("foobar".getBytes());' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'new\sPBEKeySpec\("' \
  "2_java_crypto_new-PBEKeySpec_str.txt" \
  "-i"

  grepit_search "PBEKeySpec( is used to initialize a new encryption key: instance of PBEKeySpec, often passed in the first argument as a byte[], which is the actual key" \
  'new PBEKeySpec(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'new\sPBEKeySpec\(' \
  "4_java_crypto_new-PBEKeySpec.txt" \
  "-i"

  grepit_search "GenerateKey is another form of making a new instance of SecretKey, depending on the use case randomly generates one on the fly. It's interesting to see where the key goes next, where it's stored or accidentially written to a log file." \
  '.generateKey()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.generateKey\(' \
  "4_java_crypto_generateKey.txt"

  grepit_search "Occurences of KeyGenerator.getInstance(ALGORITHM) it's interesting to see where the key goes next, where it's stored or accidentially written to a log file. Make sure the cipher is secure." \
  'KeyGenerator.getInstance(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'KeyGenerator\.getInstance\(' \
  "5_java_crypto_keygenerator-getinstance.txt"

  grepit_search "Occurences of Cipher.getInstance(ALGORITHM) it's interesting to see where the key goes next, where it's stored or accidentially written to a log file. Make sure the cipher is secure." \
  'Cipher.getInstance("RSA/NONE/NoPadding");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Cipher\.getInstance\(' \
  "5_java_crypto_cipher_getInstance.txt"

  grepit_search "The Random class shouldn't be used for crypthography in Java, the SecureRandom should be used instead." \
  'Random random = new Random();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'new Random\(' \
  "6_java_crypto_random.txt"

  grepit_search "The Math.random class shouldn't be used for crypthography in Java, the SecureRandom should be used instead." \
  'Math.random();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Math.random\(' \
  "6_java_math_random.txt"

  grepit_search "Message digest is used to generate hashes" \
  'messagedigest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'messagedigest' \
  "5_java_crypto_messagedigest.txt" \
  "-i"

  grepit_search "KeyPairGenerator, well, to generate key pairs, see http://docs.oracle.com/javase/7/docs/api/java/security/KeyPairGenerator.html . It's interesting to see where the key goes next, where it's stored or accidentially written to a log file." \
  'KeyPairGenerator(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'KeyPairGenerator\(' \
  "5_java_crypto_keypairgenerator.txt"

  grepit_search "String comparisons have to be done with .equals() in Java, not with == (won't work). Attention: False positives often occur if you used a decompiler to get the Java code, additionally it's allowed in JavaScript." \
  '  toString(  )  ==' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "toString\(\s{0,${WILDCARD_SHORT}}}\)\s{0,${WILDCARD_SHORT}}}==" \
  "9_java_string_comparison1.txt"

  grepit_search "String comparisons have to be done with .equals() in Java, not with == (won't work). Attention: False positives often occur if you used a decompiler to get the Java code, additionally it's allowed in JavaScript." \
  ' ==   toString() ' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "==\s{0,${WILDCARD_SHORT}}}toString\(\s{0,${WILDCARD_SHORT}}}\)" \
  "9_java_string_comparison2.txt"

  grepit_search "String comparisons have to be done with .equals() in Java, not with == (won't work). Attention: False positives often occur if you used a decompiler to get the Java code, additionally it's allowed in JavaScript." \
  ' ==   "' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "==\s{0,${WILDCARD_SHORT}}}\"" \
  "9_java_string_comparison3.txt"

  grepit_search "Problem with equals and equalsIgnoreCase for checking user supplied passwords or Hashes or HMACs or XYZ is that it is not a time-consistent method, therefore allowing timing attacks." \
  '.equals(hash_from_request)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "equals\(.{0,${WILDCARD_SHORT}}}[Hh][Aa][Ss][Hh]" \
  "2_java_string_comparison_equals_hash.txt"

  grepit_search "Problem with equals and equalsIgnoreCase for checking user supplied passwords or Hashes or HMACs or XYZ is that it is not a time-consistent method, therefore allowing timing attacks." \
  '.equalsIgnoreCase(hash_from_request' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "equalsIgnoreCase\(.{0,${WILDCARD_SHORT}}}[Hh][Aa][Ss][Hh]" \
  "2_java_string_comparison_equalsIgnoreCase_hash.txt"

  grepit_search "String comparisons: Filters and conditional decisions on user input should better be done with .equalsIgnoreCase() in Java in most cases, so that the clause doesn't miss something (e.g. think about string comparison in filters) or long switch case. Another problem with equals and equalsIgnoreCase for checking user supplied passwords or Hashes or HMACs or XYZ is that it is not a time-consistent method, therefore allowing timing attacks. Then there is also the question of different systems handling/doing Unicode Normalization (see for example https://gosecure.github.io/unicode-pentester-cheatsheet/ and https://www.gosecure.net/blog/2020/08/04/unicode-for-security-professionals/) or not: B\xC3\xBCcher and B\x75\xcc\x88cher is both UTF-8, but one is the character for a real Unicode u-Umlaut while the other is u[COMBINING DIAERESIS]. If the backend normalizes it could be that identifiers clash." \
  '.equals(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'equals\(' \
  "6_java_string_comparison_equals.txt"

  grepit_search "String comparisons: Filters and conditional decisions on user input should better be done with .equalsIgnoreCase() in Java in most cases, so that the clause doesn't miss something (e.g. think about string comparison in filters) or long switch case. Another problem with equals and equalsIgnoreCase for checking user supplied passwords or Hashes or HMACs or XYZ is that it is not a time-consistent method, therefore allowing timing attacks. Then there is also the question of different systems handling/doing Unicode Normalization (see for example https://gosecure.github.io/unicode-pentester-cheatsheet/ and https://www.gosecure.net/blog/2020/08/04/unicode-for-security-professionals/) or not: B\xC3\xBCcher and B\x75\xcc\x88cher is both UTF-8, but one is the character for a real Unicode u-Umlaut while the other is u[COMBINING DIAERESIS]. If the backend normalizes it could be that identifiers clash." \
  '.equalsIgnoreCase(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'equalsIgnoreCase\(' \
  "6_java_string_comparison_equalsIgnoreCase.txt"

  grepit_search "The syntax for SQL executions start with execute and this should as well catch generic execute calls." \
  'executeBlaBla(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "execute.{0,${WILDCARD_SHORT}}}\(" \
  "6_java_sql_execute.txt"

  grepit_search "If a developer catches SQL exceptions, this could mean that she tries to hide SQL injections or similar." \
  'SQLSyntaxErrorException' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SQL.{0,${WILDCARD_SHORT}}}Exception" \
  "6_java_sql_exception.txt"

  grepit_search "SQL syntax" \
  'addBatch(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "addBatch\(" \
  "6_java_sql_addBatch.txt"

  grepit_search "SQL prepared statements, can go wrong if you prepare after you use user supplied input in the query syntax..." \
  'prepareStatement(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "prepareStatement\(" \
  "6_java_sql_prepareStatement.txt"

  grepit_search "Method to set HTTP headers in Java" \
  '.setHeader(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.setHeader\(" \
  "4_java_http_setHeader.txt"

  grepit_search "Method to set HTTP headers in Java" \
  '.addCookie(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.addCookie\(" \
  "6_java_http_addCookie.txt"

  grepit_search "Method to send HTTP redirect in Java" \
  '.sendRedirect(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.sendRedirect\(" \
  "5_java_http_sendRedirect.txt"

  grepit_search "Java add HTTP header" \
  '.addHeader(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.addHeader\(" \
  "5_java_http_addHeader.txt"

  grepit_search "Java add Access-Control-Allow-Origin HTTP header, if set to * then authentication should not be done with authentication sharing mechanisms such as cookies in browsers" \
  '.addHeader("Access-Control-Allow-Origin", "*")' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.addHeader\(\"Access-Control-Allow-Origin" \
  "3_java_http_addHeader_access_control_allow_origin.txt"

  grepit_search "Java get HTTP header" \
  '.getHeaders(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getHeaders\(" \
  "5_java_http_getHeaders.txt"

  grepit_search "Java get HTTP cookies" \
  '.getCookies(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getCookies\(" \
  "5_java_http_getCookies.txt"

  grepit_search "Java get remote host" \
  '.getRemoteHost(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getRemoteHost\(" \
  "5_java_http_getRemoteHost.txt"

  grepit_search "Java get remote user" \
  '.getRemoteUser(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getRemoteUser\(" \
  "5_java_http_getRemoteUser.txt"

  grepit_search "Java is secure" \
  '.isSecure(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.isSecure\(" \
  "5_java_http_isSecure.txt"

  grepit_search "Java get requested session ID" \
  '.getRequestedSessionId(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getRequestedSessionId\(" \
  "5_java_http_getRequestedSessionId.txt"

  grepit_search "Java get content type" \
  '.getContentType(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getContentType\(" \
  "6_java_http_getContentType.txt"

  grepit_search "Java HTTP or XML local name" \
  '.getLocalName(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getLocalName\(" \
  "6_java_http_getLocalName.txt"

  grepit_search "Java generic parameter fetching" \
  '.getParameterBlabla(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getParameter.{0,${WILDCARD_SHORT}}}\(" \
  "7_java_http_getParameter.txt"

  grepit_search "Potential tainted input in string format." \
  'String.format("bla-%s"+taintedInput, variable);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "String\.format\(\s{0,${WILDCARD_SHORT}}}\"[^\"]{1,${WILDCARD_LONG}}\"\s{0,${WILDCARD_SHORT}}}\+" \
  "4_java_format_string1.txt"

  grepit_search "Potential tainted input in string format." \
  'String.format(variable)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "String\.format\(\s{0,${WILDCARD_SHORT}}}[^\"]" \
  "5_java_format_string2.txt"

  grepit_search "Java ProcessBuilder" \
  'ProcessBuilder' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ProcessBuilder' \
  "6_java_ProcessBuilder.txt" \
  "-i"

  grepit_search "HTTP session timeout" \
  'setMaxInactiveInterval()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'setMaxInactiveInterval\(' \
  "4_java_servlet_setMaxInactiveInterval.txt"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "Find out which Java Beans get persisted with javax.persistence" \
  '@Entity' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@Entity|@ManyToOne|@OneToMany|@OneToOne|@Table|@Column' \
  "7_java_persistent_beans.txt" \
  "-l" #Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "The source code shows the database table/column names... e.g. if you find a sql injection later on, this will help for the exploitation" \
  '@Column(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@Column\(' \
  "6_java_persistent_columns_in_database.txt"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "The source code shows the database table/column names... e.g. if you find a sql injection later on, this will help for the exploitation" \
  '@Table(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@Table\(' \
  "6_java_persistent_tables_in_database.txt"

  grepit_search "Find out which Java classes do any kind of io" \
  'java.net.' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'java\.net\.' \
  "8_java_io_java_net.txt" \
  "-l" # Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files

  grepit_search "Find out which Java classes do any kind of io" \
  'java.io.' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'java\.io\.' \
  "8_java_io_java_io.txt" \
  "-l" # Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files

  grepit_search "Find out which Java classes do any kind of io" \
  'javax.servlet' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'javax\.servlet' \
  "8_java_io_javax_servlet.txt" \
  "-l" # Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files

  grepit_search "Find out which Java classes do any kind of io" \
  'org.apache.http' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'org\.apache\.http' \
  "8_java_io_apache_http.txt" \
  "-l" # Special case, we only want to know matching files to know which beans get persisted, therefore -l to output matching files

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String password' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}password" \
  "7_java_confidential_data_in_strings_password.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String secret' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}secret" \
  "7_java_confidential_data_in_strings_secret.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String key' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}key" \
  "7_java_confidential_data_in_strings_key.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String cvv' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}cvv" \
  "7_java_confidential_data_in_strings_cvv.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String user' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}user" \
  "7_java_confidential_data_in_strings_user.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String passcode' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}passcode" \
  "7_java_confidential_data_in_strings_passcode.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String passphrase' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}passphrase" \
  "7_java_confidential_data_in_strings_passphrase.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String pin' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}pin" \
  "7_java_confidential_data_in_strings_pin.txt" \
  "-i"

  grepit_search "Especially for high security applications. From http://docs.oracle.com/javase/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx : \"It would seem logical to collect and store the password in an object of type java.lang.String. However, here's the caveat: Objects of type String are immutable, i.e., there are no methods defined that allow you to change (overwrite) or zero out the contents of a String after usage. This feature makes String objects unsuitable for storing security sensitive information such as user passwords. You should always collect and store security sensitive information in a char array instead.\" " \
  'String creditcard_number' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string .{0,${WILDCARD_SHORT}}}credit" \
  "7_java_confidential_data_in_strings_credit.txt" \
  "-i"

  grepit_search "SSLSocketFactory means in general you will skip SSL hostname verification because the SSLSocketFactory can't know which protocol (HTTP/LDAP/etc.) and therefore can't lookup the hostname. Even Apache's HttpClient version 3 for Java is broken: see https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
  'SSLSocketFactory' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SSLSocketFactory' \
  "6_java_SSLSocketFactory.txt"

  grepit_search "Apache's NoopHostnameVerifier makes TLS verification ignore the hostname, which is obviously very bad and allow MITM" \
  'import org.apache.http.conn.ssl.NoopHostnameVerifier' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NoopHostnameVerifier' \
  "3_java_NoopHostnameVerifier.txt"

  grepit_search "It's very easy to construct a backdoor in Java with Unicode \u characters, even within multi line comments, see http://pastebin.com/iGQhuUGd and https://plus.google.com/111673599544007386234/posts/ZeXvRCRZ3LF ." \
  '\u0041\u0042' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\\u00..\\u00..' \
  "9_java_backdoor_as_unicode.txt" \
  "-i"

  grepit_search "CheckValidity method of X509Certificate in Java is a very confusing naming for developers new to SSL/TLS and has been used as the *only* check to see if a certificate is valid or not in the past. This method *only* checks the date-validity, see http://docs.oracle.com/javase/7/docs/api/java/security/cert/X509Certificate.html#checkValidity%28%29 : 'Checks that the certificate is currently valid. It is if the current date and time are within the validity period given in the certificate.'" \
  'paramArrayOfX509Certificate[0].checkValidity(); return;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.checkValidity\(" \
  "4_java_ssl_checkValidity.txt"

  grepit_search "CheckServerTrusted, often used for certificate pinning on Java and Android, however, this is very very often insecure and not effective, see https://www.cigital.com/blog/ineffective-certificate-pinning-implementations/ . The correct method is to replace the system's TrustStore." \
  'checkServerTrusted(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "checkServerTrusted\(" \
  "4_java_checkServerTrusted.txt"

  grepit_search "getPeerCertificates, often used for certificate pinning on Java and Android, however, this is very very often insecure and not effective, see https://www.cigital.com/blog/ineffective-certificate-pinning-implementations/ . The correct method is to replace the system's TrustStore." \
  'getPeerCertificates(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "getPeerCertificates\(" \
  "4_java_getPeerCertificates.txt"

  grepit_search "getPeerCertificateChain, often used for certificate pinning on Java and Android, however, this is very very often insecure and not effective, see https://www.cigital.com/blog/ineffective-certificate-pinning-implementations/ . The correct method is to replace the system's TrustStore." \
  'getPeerCertificateChain(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "getPeerCertificateChain\(" \
  "4_java_getPeerCertificateChain.txt"

  grepit_search "A simple search for getRuntime(), which is often used later on for .exec()" \
  'getRuntime()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'getRuntime\(' \
  "7_java_getruntime.txt"

  grepit_search "A simple search for getRuntime().exec()" \
  'getRuntime().exec()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'getRuntime\(\)\.exec\(' \
  "6_java_runtime_exec_1.txt"

  grepit_search "A search for Process p = r.exec()" \
  'Process p = r.exec(args1);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Process.{0,${WILDCARD_SHORT}}}\.exec\(" \
  "6_java_runtime_exec_2.txt"

  grepit_search "The function openProcess is included in apache commons and does a getRuntime().exec" \
  'p = openProcess(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openProcess\(" \
  "7_java_apache_common_openProcess.txt"

  grepit_search "Validation in Java can be done via javax.validation. " \
  'import javax.validation.bla;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "javax.validation" \
  "5_java_javax-validation.txt"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search 'Setting values in Java objects from HTTP/JSON requests directly can be very dangerous. This is usually a fasterxml.jackson binding. These properties might be secret inputs the server accepts, but are unlinked in the client side JavaScript code. For example imagine such an annotation on the username attribute of a User Java class. This would allow to fake the username by sending a username attribute in the JSON payload.' \
  '@JsonProperty("version")' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@JsonProperty\(' \
  "4_java_jsonproperty_annotation.txt"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search 'Validation in Java can be done via certain @constraint' \
  '@constraint' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@constraint' \
  "5_java_constraint_annotation.txt"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search 'Lint will sometimes complain about security related stuff, this annotation deactivates the warning' \
  '@SuppressLint' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@SuppressLint' \
  "6_java_suppresslint.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  'new ObjectOutputStream(abc);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'new ObjectOutputStream' \
  "5_java_serialization-objectOutputStream.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  'abc.writeObject(def);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.writeObject\(' \
  "5_java_serialization-writeObject.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  'abc.readObject(def);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.readObject\(' \
  "7_java_serialization-readObject.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  ' @SerializedName("variableName")' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@SerializedName\(' \
  "5_java_serialization-SerializedName.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, readResolve is a one of the Java APIs' \
  '.readResolve(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.readResolve\(' \
  "5_java_serialization-readResolve.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, readExternal is a one of the Java APIs' \
  '.readExternal(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.readExternal\(' \
  "5_java_serialization-readExternal.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, readUnshared is a one of the Java APIs' \
  '.readUnshared(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.readUnshared\(' \
  "5_java_serialization-readUnshared.txt"

  grepit_search 'Deserialization is something that can result in remote command execution, XStream is a one of the Java APIs' \
  'XStream(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'XStream' \
  "5_java_serialization-XStream.txt"

  grepit_search 'Java serialized data? Usually Java serialized data in base64 format starts with rO0 or non-base64 with hex ACED0005. Deserialization is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  'rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAJP4=' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'rO0' \
  "4_java_serialization-base64serialized-data.txt"

  grepit_search 'Java serialized data? Usually Java serialized data in base64 format starts with rO0 or non-base64 with hex ACED0005. Deserialization is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  'ACED0005' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'AC ?ED ?00 ?05' \
  "4_java_serialization-hexserialized-data.txt" \
  "-i"

  grepit_search 'Java serialized data? Usually Java serialized data in base64 format starts with rO0 or non-base64 with hex ACED0005. Decidezation is something that can result in remote command execution, there are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  '\xAC\xED\x00\x05' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\\xAC\\xED\\x00\\x05' \
  "4_java_serialization-serialized-data.txt"

  grepit_search 'JMXInvokerServlet is a JBoss interface that is usually vulnerable to Java deserialization attacks. There are various exploits for such things, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  'JMXInvokerServlet' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'JMXInvokerServlet' \
  "2_java_serialization-JMXInvokerServlet.txt"

  grepit_search 'InvokerTransformer is a vulnerable commons collection class that can be exploited if the web application has a Java object deserialization interface/issue, see http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ and https://github.com/mbechler/marshalsec for example' \
  'InvokerTransformer' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'InvokerTransformer' \
  "2_java_serialization-invokertransformer.txt"

  grepit_search 'File.createTempFile is prone to race condition under certain circumstances, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'File.createTempFile();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.createTempFile\(' \
  "7_java_createTempFile.txt"

  grepit_search 'HttpServletRequest.getRequestedSessionId returns the session ID requested by the client in the HTTP cookie header, not the one set by the server, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'HttpServletRequest.getRequestedSessionId();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getRequestedSessionId\(' \
  "4_java_getRequestedSessionId.txt"

  grepit_search 'NullCipher is obviously a cipher that is not secure, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'new NullCipher();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NullCipher' \
  "4_java_NullCipher.txt"

  grepit_search 'Dynamic class loading/reflection, maybe from untrusted source?, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'Class c = Class.forName(cn);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Class\.forName' \
  "4_java_class_forName.txt"

  grepit_search 'Dynamic class loading/reflection and then invoking method? Maybe from untrusted source?' \
  'meth.invoke(obj, ...);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.invoke\(' \
  "5_java_invoke.txt"

  grepit_search 'New cookie should automatically be followed by c.setSecure(true); to make sure the secure flag ist set, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'Cookie c = new Cookie(a, b);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'new\sCookie\(' \
  "5_java_new_cookie.txt"

  grepit_search 'Servlet methods that throw exceptions might reveal sensitive information, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "void do.{0,${WILDCARD_LONG}}throws.{0,${WILDCARD_LONG}}ServletException" \
  "5_java_servlet_exception.txt"

  grepit_search 'Security decisions should not be done based on the HTTP referer header as it is attacker chosen, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'String referer = request.getHeader("referer");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getHeader\("referer' \
  "4_java_getHeader_referer.txt"

  grepit_search 'Usually it is a bad idea to subclass cryptographic implementation, developers might break the implementation, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'MyCryptographicAlgorithm extends MessageDigest {' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "extends.{0,${WILDCARD_LONG}}MessageDigest" \
  "5_java_extends_MessageDigest.txt"

  grepit_search 'Usually it is a bad idea to subclass cryptographic implementation, developers might break the implementation, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=java' \
  'MyCryptographicAlgorithm extends WhateverCipher {' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "extends.{0,${WILDCARD_LONG}}cipher" \
  "5_java_extends_cipher.txt" \
  "-i"

  grepit_search "printStackTrace logs and should not be in production (also logs to Android log), information leakage, etc." \
  '.printStackTrace()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.printStackTrace\(' \
  "7_java_printStackTrace.txt"

  grepit_search "setAttribute is usually used to set an attribute of a session object, untrusted data should not be added to a session object" \
  'session.setAttribute("abc", untrusted_input);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.setAttribute\(' \
  "6_java_setAttribute.txt"

  grepit_search "StreamTokenizer, look for parsing errors, see https://docs.oracle.com/javase/7/docs/api/java/io/StreamTokenizer.html" \
  'StreamTokenizer' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'StreamTokenizer' \
  "6_java_StreamTokenizer.txt"

  grepit_search "getResourceAsStream, see http://docs.oracle.com/javase/7/docs/api/java/lang/Class.html#getResourceAsStream(java.lang.String)" \
  'getResourceAsStream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'getResourceAsStream' \
  "6_java_getResourceAsStream.txt"

  grepit_search "JWT in Java set the signing key incorrectly. An insecurity as happened in Apache Pulsar bug CVE-2021-22160 insecurity with algorithm none meaning no signature (just nothing after the second dot in JWT)" \
  'Jwts.parserBuilder().setSigningKey(key).build().parse(jwt)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "parserBuilder\(\)\.setSigningKey\(" \
  "1_java_jwt_setSigningKey_vuln.txt"

  grepit_search "JWT in Java set the signing key. An example of an insecurity happened in Apache Pulsar bug CVE-2021-22160 insecurity with algorithm none meaning no signature (just nothing after the second dot in JWT)" \
  'Jwts.parserBuilder().setSigningKey(key).build().parse(jwt)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.setSigningKey\(" \
  "3_java_jwt_setSigningKey.txt"
}

grepit_module_jsp() {
  print_output "[*] Starting Grepit JSP module" "no_log"

  grepit_search "JSP redirect" \
  '.sendRedirect(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.sendRedirect\(' \
  "5_java_jsp_redirect.txt"

  grepit_search "JSP redirect" \
  '.forward(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.forward\(' \
  "5_java_jsp_forward_1.txt"

  grepit_search "JSP redirect" \
  ':forward' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ':forward' \
  "5_java_jsp_forward_2.txt"

  grepit_search "Can introduce XSS" \
  'escape=false' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "escape\s{0,${WILDCARD_SHORT}}}=\s{0,${WILDCARD_SHORT}}}'?\"?\s{0,${WILDCARD_SHORT}}}false" \
  "2_java_jsp_xss_escape.txt" \
  "-i"

  grepit_search "Can introduce XSS" \
  'escapeXml=false' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "escapeXml\s{0,${WILDCARD_SHORT}}}=\s{0,${WILDCARD_SHORT}}}'?\"?\s{0,${WILDCARD_SHORT}}}false" \
  "2_java_jsp_xss_escapexml.txt" \
  "-i"

  grepit_search "Can introduce XSS when simply writing a bean property to HTML without escaping. Attention: there are now client-side JavaScript libraries using the same tags for templates!" \
  '<%=bean.getName()%>' \
  'Attention: there are now client-side JavaScript libraries using the same tags for templates!' \
  "<%=\s{0,${WILDCARD_SHORT}}}[A-Za-z0-9_]{1,${WILDCARD_LONG}}.get[A-Za-z0-9_]{1,${WILDCARD_LONG}}\(" \
  "1_java_jsp_property_to_html_xss.txt" \
  "-i"

  grepit_search "Java generic JSP parameter get" \
  '.getParameter(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getParameter\(" \
  "5_java_jsp_property_to_html_xss.txt" \
  "-i"

  grepit_search "Can introduce XSS when simply writing a bean property to HTML without escaping." \
  'out.print("<option "+bean.getName()+"=jjjj");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "out.printl?n?\(\"<.{1,${WILDCARD_LONG}}\+.{1,${WILDCARD_LONG}}\);" \
  "1_java_jsp_out_print_to_html_xss2.txt" \
  "-i"

  grepit_search "JSP file upload" \
  '<s:file test' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "<s:file\s" \
  "4_java_jsp_file_upload.txt" \
  "-i"
}

grepit_module_java_spring() {
  print_output "[*] Starting Grepit Java Spring module" "no_log"

  grepit_search "DataBinder.setAllowedFields. See e.g. http://blog.fortify.com/blog/2012/03/23/Mass-Assignment-Its-Not-Just-For-Rails-Anymore ." \
  'DataBinder.setAllowedFields' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'DataBinder\.setAllowedFields' \
  "4_java_spring_mass_assignment.txt" \
  "-i"

  grepit_search "stripUnsafeHTML, method of the Spring Surf Framework can introduce things like XSS, because it is not really protecting." \
  'stripUnsafeHTML' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stripUnsafeHTML' \
  "2_java_spring_stripUnsafeHTML.txt" \
  "-i"

  grepit_search "stripEncodeUnsafeHTML, method of the Spring Surf Framework can introduce thinks like XSS, because it is not really protecting." \
  'stripEncodeUnsafeHTML' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stripEncodeUnsafeHTML' \
  "2_java_spring_stripEncodeUnsafeHTML.txt" \
  "-i"

  grepit_search "RequestMapping method of the Spring Surf Framework to see how request URLs are mapped to classes." \
  '@RequestMapping(method=RequestMethod.GET, value={"/user","/user/{id}"})' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@RequestMapping\(' \
  "5_java_spring_requestMapping.txt"

  grepit_search "ServletMapping XML of the Spring Surf Framework to see how request URLs are mapped to classes." \
  '<servlet-mapping><servlet-name>spring</servlet-name><url-pattern>*.html</url-pattern><url-pattern>/gallery/*</url-pattern><url-pattern>/galleryupload/*</url-pattern>' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '<servlet-mapping>' \
  "5_java_spring_servletMapping.txt"

  grepit_search "HttpSecurity is used to configure the Spring HTTP security context, such as disabling CSRF protections" \
  'protected void configure(HttpSecurity http) throws Exception { http.csrf().disable();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'HttpSecurity' \
  "3_java_spring_HttpSecurity.txt"

  grepit_search "WebSecurityConfigurerAdapter is used to configure the Spring HTTP security context, such as disabling CSRF protections" \
  'import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter; public class SpringWebSecurityConfiguration extends WebSecurityConfigurerAdapter {' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'WebSecurityConfigurerAdapter' \
  "3_java_spring_WebSecurityConfigurerAdapter.txt"

  grepit_search "PasswordEncoder is to check user passwords in Spring (import org.springframework.security.crypto.password.PasswordEncoder)" \
  'PasswordEncoder' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'PasswordEncoder' \
  "3_java_spring_PasswordEncoder.txt"

  grepit_search "Spring getHeader to get HTTP header from a request" \
  '.getHeader("foobar")' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.getHeader\(" \
  "5_java_spring_http_getHeader.txt"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "Check for Spring View Manipulation https://github.com/veracode-research/spring-view-manipulation/" \
  '@GetMapping("/safe/redirect")' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@GetMapping\(' \
  "2_java_spring_view_manipulation.txt"
}

grepit_module_java_struts() {
  print_output "[*] Starting Grepit Java Struts module" "no_log"

  grepit_search "Action mappings for struts where the validation is disabled" \
  'validate  =  "false' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "validate\s{0,${WILDCARD_SHORT}}}=\s{0,${WILDCARD_SHORT}}}'?\"?false" \
  "3_java_struts_deactivated_validation.txt" \
  "-i"

  grepit_search "see e.g. http://erpscan.com/press-center/struts2-devmode-rce-with-metasploit-module/" \
  'struts.devMode' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "struts\.devMode" \
  "3_java_struts_devMode.txt" \
  "-i"
}

grepit_module_flex_flash() {
  print_output "[*] Starting Grepit FLEX Flash module" "no_log"

  grepit_search 'Flex Flash has Security.allowDomain that should be tightly set and for sure not to *, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=flex' \
  'Security.allowDomain("*");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Security\.allowDomain' \
  "4_flex_security_allowDomain.txt"

  grepit_search 'Flex Flash has Security.allowInsecureDomain that is here for backward compatibility to allowDomain, it should be tightly set and for sure not to *, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=flex' \
  'Security.allowInsecureDomain("*");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Security\.allowInsecureDomain' \
  "4_flex_security_allowInsecureDomain.txt"

  grepit_search 'Flex Flash can load arbitrary policy files via loadPolicyFile' \
  'loadPolicyFile("http://example.com/crossdomain.xml");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'loadPolicyFile' \
  "4_flex_loadPolicyFile.txt"

  grepit_search 'Flex Flash permitted-cross-domain-policies' \
  'permitted-cross-domain-policies' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'permitted-cross-domain-policies' \
  "4_flex_permitted-cross-domain-policies.txt"

  grepit_search 'Flex Flash has trace to output debug info, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=flex' \
  'trace("output:" + value);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'trace\(' \
  "6_flex_trace.txt"

  grepit_search 'ExactSettings to false makes cross-domain attacks possible, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=flex' \
  'Security.exactSettings = false;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Security\.exactSettings' \
  "4_flex_exactSettings.txt"
}

grepit_module_dot_net() {
  print_output "[*] Starting Grepit .NET module" "no_log"

  grepit_search ".NET View state enable" \
  'EnableViewState' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "EnableViewState" \
  "4_dotnet_viewState.txt"

  grepit_search "Potentially dangerous request filter message is not poping up when disabled, which means XSS in a lot of cases." \
  'ValidateRequest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "ValidateRequest" \
  "3_dotnet_validate_request.txt"

  grepit_search "If you declare a variable 'unsafe' in .NET you can do pointer arythmetic and therefore introduce buffer overflows etc. again" \
  'int unsafe bla' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "unsafe\s" \
  "3_dotnet_unsafe_declaration.txt"

  grepit_search "If you use Marshal in .NET you use an unsafe API and therefore you could introduce buffer overflows etc. again." \
  'Marshal' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Marshal" \
  "4_dotnet_marshal.txt"

  grepit_search "If you use 'LayoutKind.Explicit' in .NET you can get memory corruption again, see http://weblog.ikvm.net/2008/09/13/WritingANETSecurityExploitPoC.aspx for an example" \
  '[StructLayout(LayoutKind.Explicit)]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "LayoutKind\.Explicit" \
  "3_dotnet_LayoutKind_explicit.txt"

  grepit_search "Console.WriteLine should not be used as it is only for debugging purposes, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=cs" \
  'Console.WriteLine("debug with sensitive information")' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Console\.WriteLine" \
  "4_dotnet_console_WriteLine.txt"

  grepit_search "TripleDESCryptoServiceProvider, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=cs" \
  'new TripleDESCryptoServiceProvider();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TripleDESCryptoServiceProvider" \
  "4_dotnet_TripleDESCryptoServiceProvider.txt"

  grepit_search "unchecked allows to disable exceptions for integer overflows, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=cs" \
  'int d = unchecked(list.Sum()); or also as a block unchecked { int e = list.Sum(); }' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "unchecked" \
  "4_dotnet_unchecked.txt"

  grepit_search "Code access security permission changing via reflection, also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'ReflectionPermission.MemberAccess' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "ReflectionPermission" \
  "4_dotnet_ReflectionPermission.txt"

  grepit_search "Hidden input fields for HTML, also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'system.web.ui.htmlcontrols.htmlinputhidden' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "htmlinputhidden" \
  "4_dotnet_htmlinputhidden.txt"

  grepit_search "Configuration for request encoding, also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'requestEncoding' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "requestEncoding" \
  "4_dotnet_requestEncoding.txt"

  grepit_search "Configuration for custom errors, also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'CustomErrors' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CustomErrors" \
  "4_dotnet_CustomErrors.txt"

  grepit_search "Used for IO in .NET, also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'ObjectInputStream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "ObjectInputStream" \
  "5_dotnet_ObjectInputStream.txt"

  grepit_search "Used for IO in .NET, also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'pipedinputstream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pipedinputstream" \
  "4_dotnet_pipedinputstream.txt"

  grepit_search "Used for IO in .NET, also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'objectstream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "objectstream" \
  "4_dotnet_objectstream.txt"

  grepit_search "Authentication as specified on https://msdn.microsoft.com/en-us/library/aa289844(v=vs.71).aspx , also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'Application_OnAuthenticateRequest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AuthenticateRequest" \
  "4_dotnet_AuthenticateRequest.txt"

  grepit_search "Authorization as specified on https://msdn.microsoft.com/en-us/library/system.web.httpapplication.authorizerequest(v=vs.110).aspx , also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'AuthorizeRequest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AuthorizeRequest" \
  "4_dotnet_AuthorizeRequest.txt"

  grepit_search "Session_OnStart as specified on https://msdn.microsoft.com/en-us/library/ms524776(v=vs.90).aspx , also one of the rules of https://www.owasp.org/index.php/Category:OWASP_Code_Crawler" \
  'Session_OnStart' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Session_OnStart" \
  "4_dotnet_Session_OnStart.txt"

  grepit_search "SecurityCriticalAttribute as specified on https://msdn.microsoft.com/en-us/library/system.security.securitycriticalattribute.aspx" \
  'SecurityCriticalAttribute' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SecurityCriticalAttribute" \
  "4_dotnet_SecurityCriticalAttribute.txt"

  grepit_search "SecurityPermission as specified on https://msdn.microsoft.com/en-us/library/system.security.permissions.securitypermission(v=vs.110).aspx" \
  'SecurityPermission' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SecurityPermission" \
  "4_dotnet_SecurityPermission.txt"

  grepit_search "SecurityAction as specified on https://msdn.microsoft.com/en-us/library/ms182303(v=vs.80).aspx" \
  '[EnvironmentPermissionAttribute(SecurityAction.LinkDemand, Unrestricted=true)]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SecurityAction" \
  "4_dotnet_SecurityAction.txt"

  grepit_search "Unmanaged memory pointers with IntPtr/UIntPtr, see https://msdn.microsoft.com/en-us/library/ms182306(v=vs.80).aspx" \
  'public IntPtr publicPointer1;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "IntPtr" \
  "4_dotnet_IntPtr.txt"

  grepit_search "SQLClient, see https://msdn.microsoft.com/en-us/library/ms182310(v=vs.80).aspx" \
  'using System.Data.SqlClient;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SqlClient" \
  "4_dotnet_SqlClient.txt"

  grepit_search "SQL injection found in a web application the wild: Using string.Format instead of SqlParameter leading to non-prepared SQL statement which is later executed" \
  'string.Format("SELECT * FROM [a].[b] ab ORDER BY {0} {1} OFFSET {2} ROWS FETCH NEXT {3} ROWS ONLY;", new object[4]{(object) x, (object) y, (object) z, (object) u});' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "string\.Format\(.{0,${WILDCARD_SHORT}}}SELECT.{0,${WILDCARD_LONG}}FROM" \
  "1_dotnet_stringformat_sqli.txt" \
  "-i"

  grepit_search "SuppressUnmanagedCodeSecurityAttribute, see https://msdn.microsoft.com/en-us/library/ms182311(v=vs.80).aspx" \
  '[SuppressUnmanagedCodeSecurityAttribute()]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SuppressUnmanagedCodeSecurityAttribute" \
  "2_dotnet_SuppressUnmanagedCodeSecurityAttribute.txt"

  grepit_search "UnmanagedCode, see https://msdn.microsoft.com/en-us/library/ms182312(v=vs.80).aspx" \
  '[SecurityPermissionAttribute(SecurityAction.Demand, UnmanagedCode=true)]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "UnmanagedCode" \
  "4_dotnet_UnmanagedCode.txt"

  grepit_search "Serializable, see https://msdn.microsoft.com/en-us/library/ms182315(v=vs.80).aspx" \
  '[Serializable]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Serializable" \
  "4_dotnet_Serializable.txt"

  grepit_search "CharSet.Auto, see https://msdn.microsoft.com/en-us/library/ms182319(v=vs.80).aspx" \
  '[DllImport("advapi32.dll", CharSet=CharSet.Auto)]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CharSet\.Auto" \
  "4_dotnet_CharSet_Auto.txt"

  grepit_search "DllImport, interesting to see in general, additionally see https://msdn.microsoft.com/en-us/library/ms182319(v=vs.80).aspx" \
  '[DllImport("advapi32.dll", CharSet=CharSet.Auto)]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "DllImport" \
  "4_dotnet_DllImport.txt"
}

# - php functions are case insensitive: ImAgEcReAtEfRoMpNg()
# - whitespaces can occur everywhere, eg. 5.5 (-> 5.5) is different from 5 . 5 (-> "55"), see http://stackoverflow.com/questions/4884987/php-whitespaces-that-do-matter
grepit_module_php() {
  print_output "[*] Starting Grepit PHP module" "no_log"

  grepit_search "Tainted input, GET URL parameter" \
  '$_GET' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\$_GET' \
  "5_php_get.txt"

  grepit_search "Tainted input, POST parameter" \
  '$_POST' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\$_POST' \
  "5_php_post.txt"

  grepit_search "Tainted input, cookie parameter" \
  '$_COOKIE' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\$_COOKIE' \
  "5_php_cookie.txt"

  grepit_search "Tainted input. Using \$_REQUEST is a bad idea in general, as that means GET/POST exchangeable and transporting sensitive information in the URL is a bad idea (see HTTP RFC -> ends up in logs, browser history, etc.)." \
  '$_REQUEST' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\$_REQUEST' \
  "5_php_request.txt"

  grepit_search "Dangerous PHP function: proc_" \
  'proc_' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'proc_' \
  "4_php_proc.txt" \
  "-i"

  grepit_search "Dangerous PHP function: passthru" \
  'passthru(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "passthru\s{0,${WILDCARD_SHORT}}}\(" \
  "2_php_passthru.txt" \
  "-i"

  grepit_search "Dangerous PHP function: escapeshell" \
  'escapeshell' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'escapeshell' \
  "3_php_escapeshell.txt" \
  "-i"

  grepit_search "Dangerous PHP function: fopen" \
  'fopen(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "fopen\s{0,${WILDCARD_SHORT}}}\(" \
  "3_php_fopen.txt" \
  "-i"

  grepit_search "Dangerous PHP function: file_get_contents" \
  'file_get_contents (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "file_get_contents\s{0,${WILDCARD_SHORT}}}\(" \
  "4_php_file_get_contents.txt" \
  "-i"

  grepit_search "Dangerous PHP function: imagecreatefrom" \
  'imagecreatefrom' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'imagecreatefrom' \
  "5_php_imagecreatefrom.txt" \
  "-i"

  grepit_search "Dangerous PHP function: mkdir" \
  'mkdir (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "mkdir\s{0,${WILDCARD_SHORT}}}\(" \
  "6_php_mkdir.txt" \
  "-i"

  grepit_search "Dangerous PHP function: chmod" \
  'chmod (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "chmod\s{0,${WILDCARD_SHORT}}}\(" \
  "6_php_chmod.txt" \
  "-i"

  grepit_search "Dangerous PHP function: chown" \
  'chown (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "chown\s{0,${WILDCARD_SHORT}}}\(" \
  "6_php_chown.txt" \
  "-i"

  grepit_search "Dangerous PHP function: file" \
  'file (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "file\s{0,${WILDCARD_SHORT}}}\(" \
  "8_php_file.txt" \
  "-i"

  grepit_search "Dangerous PHP function: link" \
  'link (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "link\s{0,${WILDCARD_SHORT}}}\(" \
  "5_php_link.txt" \
  "-i"

  grepit_search "Dangerous PHP function: rmdir" \
  'rmdir (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "rmdir\s{0,${WILDCARD_SHORT}}}\(" \
  "6_php_rmdir.txt" \
  "-i"

  grepit_search "CURLOPT_SSL_VERIFYPEER should be set to TRUE, CURLOPT_SSL_VERIFYHOST should be set to 2, if there is a mixup, this can go really wrong. See https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
  'CURLOPT_SSL_VERIFYPEER' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CURLOPT_SSL_VERIFYPEER' \
  "2_php_verifypeer-verifypeer.txt" \
  "-i"

  grepit_search "CURLOPT_SSL_VERIFYPEER should be set to TRUE, CURLOPT_SSL_VERIFYHOST should be set to 2, if there is a mixup, this can go really wrong. See https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
  'CURLOPT_SSL_VERIFYHOST' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CURLOPT_SSL_VERIFYHOST' \
  "2_php_verifypeer-verifyhost.txt" \
  "-i"

  grepit_search "gnutls_certificate_verify_peers, see https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
  'gnutls_certificate_verify_peers' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'gnutls_certificate_verify_peers' \
  "2_php_gnutls-certificate-verify-peers.txt" \
  "-i"

  grepit_search "fsockopen is not checking server certificates if used with a ssl:// URL. See https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html" \
  'fsockopen (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "fsockopen\s{0,${WILDCARD_SHORT}}}\(" \
  "1_php_fsockopen.txt" \
  "-i"

  grepit_search "You can make a lot of things wrong with include" \
  'include (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "include\s{0,${WILDCARD_SHORT}}}\(" \
  "5_php_include.txt" \
  "-i"

  grepit_search "You can make a lot of things wrong with include_once" \
  'include_once (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "include_once\s{0,${WILDCARD_SHORT}}}\(" \
  "5_php_include_once.txt" \
  "-i"

  grepit_search "You can make a lot of things wrong with require" \
  'require (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "require\s{0,${WILDCARD_SHORT}}}\(" \
  "5_php_require.txt" \
  "-i"

  grepit_search "You can make a lot of things wrong with require_once" \
  'require_once (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "require_once\s{0,${WILDCARD_SHORT}}}\(" \
  "5_php_require_once.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: echo" \
  'echo' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "echo" \
  "6_php_echo_high_volume.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: echo in combination with \$_POST." \
  'echo $_POST["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "echo.{0,${WILDCARD_LONG}}\\\$_POST" \
  "1_php_echo_low_volume_POST.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: echo in combination with \$_GET." \
  'echo $_GET["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "echo.{0,${WILDCARD_LONG}}\\\$_GET" \
  "1_php_echo_low_volume_GET.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: echo in combination with \$_COOKIE. And there is no good explanation usually why a cookie is printed to the HTML anyway (debug interface?)." \
  'echo $_COOKIE["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "echo.{0,${WILDCARD_LONG}}\\\$_COOKIE" \
  "2_php_echo_low_volume_COOKIE.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: echo in combination with \$_REQUEST." \
  'echo $_REQUEST["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "echo.{0,${WILDCARD_LONG}}\\\$_REQUEST" \
  "1_php_echo_low_volume_REQUEST.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: print" \
  'print' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "print" \
  "6_php_print_high_volume.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: print in combination with \$_POST." \
  'print $_POST["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "print.{0,${WILDCARD_LONG}}\\\$_POST" \
  "1_php_print_low_volume_POST.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: print in combination with \$_GET." \
  'print $_GET["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "print.{0,${WILDCARD_LONG}}\\\$_GET" \
  "1_php_print_low_volume_GET.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: print in combination with \$_COOKIE. And there is no good explanation usually why a cookie is printed to the HTML anyway (debug interface?)." \
  'print $_COOKIE["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "print.{0,${WILDCARD_LONG}}\\\$_COOKIE" \
  "2_php_print_low_volume_COOKIE.txt" \
  "-i"

  grepit_search "Methods that often introduce XSS: print in combination with \$_REQUEST. Don't use \$_REQUEST in general." \
  'print $_REQUEST["ABC"]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "print.{0,${WILDCARD_LONG}}\\\$_REQUEST" \
  "1_php_print_low_volume_REQUEST.txt" \
  "-i"

  grepit_search "Databases in PHP: pg_query" \
  'pg_query(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pg_query\s{0,${WILDCARD_SHORT}}}\(" \
  "4_php_sql_pg_query.txt" \
  "-i"

  grepit_search "Databases in PHP: mysqli_" \
  'mysqli_method(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "mysqli_.{1,${WILDCARD_SHORT}}}\(" \
  "4_php_sql_mysqli.txt" \
  "-i"

  grepit_search "Databases in PHP: mysql_" \
  'mysql_method(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "mysql_.{1,${WILDCARD_SHORT}}}\(" \
  "4_php_sql_mysql.txt" \
  "-i"

  grepit_search "Databases in PHP: mssql_" \
  'mssql_method(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "mssql_.{1,${WILDCARD_SHORT}}}\(" \
  "4_php_sql_mssql.txt" \
  "-i"

  grepit_search "Databases in PHP: odbc_exec" \
  'odbc_exec(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "odbc_exec\s{0,${WILDCARD_SHORT}}}\(" \
  "4_php_sql_odbc_exec.txt" \
  "-i"

  grepit_search "PHP rand(): This is not a secure random." \
  'rand(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "rand\s{0,${WILDCARD_SHORT}}}\(" \
  "6_php_rand.txt" \
  "-i"

  grepit_search "Extract can be dangerous and could be used as backdoor, see http://blog.sucuri.net/2014/02/php-backdoors-hidden-with-clever-use-of-extract-function.html#null" \
  'extract(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "extract\s{0,${WILDCARD_SHORT}}}\(" \
  "5_php_extract.txt" \
  "-i"

  grepit_search "Assert can be used as backdoor, see http://rileykidd.com/2013/08/21/the-backdoor-you-didnt-grep/" \
  'assert(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "assert\s{0,${WILDCARD_SHORT}}}\(" \
  "6_php_assert.txt" \
  "-i"

  grepit_search "Preg_replace can be used as backdoor, see http://labs.sucuri.net/?note=2012-05-21" \
  'preg_replace(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "preg_replace\s{0,${WILDCARD_SHORT}}}\(" \
  "6_php_preg_replace.txt" \
  "-i"

  grepit_search "The big problem with == is that in PHP (and some other languages), this comparison is not type safe. What you should always use is ===. For example a hash value that starts with 0E could be interpreted as an integer if you don't take care. There were real world bugs exploiting this issue already, think login form and comparing the hashed user password, what happens if you type in 0 as the password and brute force different usernames until a user has a hash which starts with 0E? Then there is also the question of different systems handling/doing Unicode Normalization (see for example https://gosecure.github.io/unicode-pentester-cheatsheet/ and https://www.gosecure.net/blog/2020/08/04/unicode-for-security-professionals/) or not: B\xC3\xBCcher and B\x75\xcc\x88cher is both UTF-8, but one is the character for a real Unicode u-Umlaut while the other is u[COMBINING DIAERESIS]. If the backend normalizes it could be that identifiers clash." \
  'hashvalue_from_db == PBKDF2(password_from_login_http_request)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[^=]==[^=]" \
  "7_php_type_unsafe_comparison.txt"

  grepit_search "hash_hmac with user input. It throws a warning when the second parameter is an array instead of an exception, which is sometimes an issue as you can input arrays by using param[]=value." \
  'hash_hmac("sha256", $_POST["salt"], $secret);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "hash_hmac\s{0,${WILDCARD_SHORT}}}\(.{0,${WILDCARD_LONG}}\\\$_" \
  "2_hmac_with_user_input.txt"

  grepit_search "Execute on shell in PHP" \
  'shell_exec(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "shell_exec\s{0,${WILDCARD_SHORT}}}\(" \
  "3_php_shell_exec.txt" \
  "-i"

  grepit_search "hash_equals is time-constant hash comparison. This is probably important code." \
  'return hash_equals($hash, self::signMessage($message, $key));' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "hash_equals\s{0,${WILDCARD_SHORT}}}\(" \
  "3_php_hash_equals.txt" \
  "-i"

  grepit_search "unserialize to unserialize objects in PHP https://www.php.net/manual/en/function.unserialize.php" \
  '$vault = unserialize($data, ["allowed_classes" => Vault::class]);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "unserialize\s{0,${WILDCARD_SHORT}}}\(" \
  "3_php_unserialize.txt" \
  "-i"

  grepit_search "session_id function in PHP is used to get or set the session ID https://www.php.net/manual/en/function.session-id.php" \
  '$s = session_id();' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "session_id\s{0,${WILDCARD_SHORT}}}\(" \
  "3_php_session_id.txt" \
  "-i"
}

# The HTML/JavaScript specific stuff
grepit_module_html() {
  print_output "[*] Starting Grepit HTML module" "no_log"

  grepit_search "HTML upload." \
  'enctype="multipart/form-data"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "multipart/form-data" \
  "5_html_upload_form_tag.txt" \
  "-i"

  grepit_search "HTML upload form." \
  '<input name="param" type="file"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "type=.?file" \
  "5_html_upload_input_tag.txt" \
  "-i"

  grepit_search "Autocomplete should be set to off for password fields." \
  'autocomplete' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'autocomplete' \
  "7_html_autocomplete.txt" \
  "-i"

  grepit_search "Angular.js has this Strict Contextual Escaping (SCE) that should prevent ." \
  '$sceProvider.enabled(false)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sceProvider\.enabled\(' \
  "4_angularjs_sceprovider_enabled.txt" \
  "-i"

  grepit_search 'From the Angular.js explanation for Strict Contextual Escaping (SCE): You can then audit your code (a simple grep would do) to ensure that this is only done for those values that you can easily tell are safe - because they were received from your server, sanitized by your library, etc. [...] In the case of AngularJS SCE service, one uses {@link ng.$sce#trustAs $sce.trustAs} (and shorthand methods such as {@link ng.$sce#trustAsHtml $sce.trustAsHtml}, etc.) to obtain values that will be accepted by SCE / privileged contexts.' \
  '$sce.trustAsHtml' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sce\.trustAs' \
  "4_angularjs_sceprovider_check_all_instances_of_unsafe_html_1.txt" \
  "-i"

  grepit_search 'From the Angular.js explanation for Strict Contextual Escaping (SCE): You can then audit your code (a simple grep would do) to ensure that this is only done for those values that you can easily tell are safe - because they were received from your server, sanitized by your library, etc. [...] In the case of AngularJS SCE service, one uses {@link ng.$sce#trustAs $sce.trustAs} (and shorthand methods such as {@link ng.$sce#trustAsHtml $sce.trustAsHtml}, etc.) to obtain values that will be accepted by SCE / privileged contexts.' \
  'ng.$sce#trustAs' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sce#trustAs' \
  "4_angularjs_sceprovider_check_all_instances_of_unsafe_html_2.txt" \
  "-i"

  grepit_search 'From the Angular.js explanation for Strict Contextual Escaping (SCE): You can then audit your code (a simple grep would do) to ensure that this is only done for those values that you can easily tell are safe - because they were received from your server, sanitized by your library, etc. [...] In the case of AngularJS SCE service, one uses {@link ng.$sce#trustAs $sce.trustAs} (and shorthand methods such as {@link ng.$sce#trustAsHtml $sce.trustAsHtml}, etc.) to obtain values that will be accepted by SCE / privileged contexts. See also https://docs.angularjs.org/api/ngSanitize/service/$sanitize .' \
  '$scope.deliberatelyTrustDangerousSnippet = function() {return $sce.trustAsHtml($scope.snippet);};' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'deliberatelyTrustDangerousSnippet' \
  "2_angularjs_deliberatelyTrustDangerousSnippet.txt"

  grepit_search 'From the Angular.js explanation for HttpClientXsrfModule: For a server that supports a cookie-based XSRF protection system, use directly to configure XSRF protection with the correct cookie and header names. If no names are supplied, the default cookie name is XSRF-TOKEN and the default header name is X-XSRF-TOKEN. See also https://angular.io/api/common/http/HttpClientXsrfModule .' \
  'HttpClientXsrfModule.withOptions({' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'HttpClientXsrfModule' \
  "3_angularjs_HttpClientXsrfModule.txt"

  grepit_search 'application/octet-stream is subject to content sniffing in some browsers.' \
  'application/octet-stream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'application/octet-stream' \
  "5_html_application_octet-stream.txt" \
  "-i"

  grepit_search 'text/plain is subject to content sniffing in some browsers.' \
  'text/plain' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'text/plain' \
  "5_html_text_plain.txt" \
  "-i"
}

grepit_module_js() {
  print_output "[*] Starting Grepit JavaScript module" "no_log"

  grepit_search "Location hash: DOM-based XSS source/sink." \
  'location.hash' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'location\.hash' \
  "5_js_dom_xss_location-hash.txt"

  grepit_search "Location href: DOM-based XSS source/sink." \
  'location.href' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'location\.href' \
  "5_js_dom_xss_location-href.txt"

  grepit_search "Location pathname: DOM-based XSS source/sink." \
  'location.pathname' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'location\.pathname' \
  "5_js_dom_xss_location-pathname.txt"

  grepit_search "Location search: DOM-based XSS source/sink." \
  'location.search' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'location\.search' \
  "5_js_dom_xss_location-search.txt"

  grepit_search "appendChild: DOM-based XSS sink." \
  '.appendChild(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.appendChild\(' \
  "5_js_dom_xss_appendChild.txt"

  grepit_search "Document location: DOM-based XSS source/sink." \
  'document.location' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'document\.location' \
  "5_js_dom_xss_document_location.txt"

  grepit_search "Window location: DOM-based XSS source/sink." \
  'window.location' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'window\.location' \
  "5_js_dom_xss_window-location.txt"

  grepit_search "Document referrer: DOM-based XSS source/sink." \
  'document.referrer' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'document\.referrer' \
  "5_js_dom_xss_document-referrer.txt"

  grepit_search "Document URL: DOM-based XSS source/sink." \
  'document.URL' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'document\.URL' \
  "5_js_dom_xss_document-URL.txt"

  grepit_search "Document Write and variants of it: DOM-based XSS source/sink." \
  'document.writeln(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'document\.writel?n?\(' \
  "5_js_dom_xss_document-write.txt"

  grepit_search "InnerHTML: DOM-based XSS source/sink." \
  '.innerHTML =' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.innerHTML\s{0,${WILDCARD_SHORT}}}=" \
  "5_js_dom_xss_innerHTML.txt"

  grepit_search "DangerouslySetInnerHTML: DOM-based XSS sink for React.js basically. Simply what's innerHTML is called dangerouslySetInnerHTML in React." \
  '<div className="text" dangerouslySetInnerHTML={{ __html: text }} />' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "DangerouslySetInnerHTML" \
  "2_js_react_dom_xss_dangerouslySetInnerHTML.txt" \
  "-i"

  grepit_search "bypassSecurityTrustHtml, bypassSecurityTrustStyle, bypassSecurityTrustScript, bypassSecurityTrustUrl, bypassSecurityTrustResourceUrl: DOM-based XSS sink for Angular.js circumventing the sanitizer." \
  'this.sanitizer.bypassSecurityTrustHtml(safeHtml);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "bypassSecurityTrust" \
  "2_js_angular_dom_xss_bypassSecurityTrust.txt" \
  "-i"

  grepit_search "OuterHTML: DOM-based XSS source/sink." \
  '.outerHTML =' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.outerHTML\s{0,${WILDCARD_SHORT}}}=" \
  "5_js_dom_xss_outerHTML.txt"

  grepit_search "Console should not be logged to in production" \
  'console.log(user_password);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "console\." \
  "5_js_console.txt"

  grepit_search "The postMessage in JavaScript should explicitly not be used with targetOrigin set to * and check how messages are exchanged, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=js" \
  'aWindow.postMessage(message, "*");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.postMessage\(" \
  "5_js_postMessage.txt"

  grepit_search "The constructor for functions can be used as a replacement for eval, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=js" \
  'f = new Function("name", "return 123 + name"); ' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "new\sFunction.{0,${WILDCARD_SHORT}}}" \
  "4_js_new_function_eval.txt"

  grepit_search "Sensitive information in localStorage is not encrypted, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=js" \
  'localStorage.setItem("data", sensitive_data); ' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "localStorage" \
  "4_js_localStorage.txt"

  grepit_search "Sensitive information in sessionStorage is not encrypted, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=js" \
  'sessionStorage.setItem("data", sensitive_data); ' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sessionStorage" \
  "4_js_sessionStorage.txt"

  grepit_search "Dynamic creation of script tag, where is it loading JavaScript from?" \
  'elem = createElement("script");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "createElement.{0,${WILDCARD_SHORT}}}script" \
  "4_js_createElement_script.txt"

  grepit_search "RFC 4627 includes a parser regex example http://www.ietf.org/rfc/rfc4627.txt and it is insecure as explained in the 'the tangled web' book, as it allows incrementing and decrementing of certain variables." \
  'var my_JSON_object = !(/[^,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]/.test( var my_JSON_object = !(/[^,:{}\[\]0-9.\-+Eaeflnr-u \n\r\t]/.test(eval(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Eaeflnr-u" \
  "2_js_insecure_JSON_parser.txt"

  grepit_search "Setting the document.domain influences the same origin policy." \
  'document.domain = example.com' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "document.domain\s=" \
  "4_js_document_domain.txt"

  grepit_search "Frame communication in browsers with postMessage. PostMessage is one of the better ways of doing this." \
  'parent.postMessage("user=bob", "https://example.com");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "postMessage\(" \
  "4_js_postMessage.txt"

  grepit_search "Frame communication in browsers with postMessage and the corresponding addEventListener." \
  'addEventListener("message", a_function, false);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "addEventListener.{0,${WILDCARD_SHORT}}}message" \
  "4_js_addEventListener_message.txt"

  grepit_search "AllowScriptAccess allows or disallows ExternalInterface.call from an Applet to JavaScript." \
  'AllowScriptAccess' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AllowScriptAccess" \
  "4_js_AllowScriptAccess.txt"

  grepit_search "The mayscript attribute of <applet>, <embed> and <object> should be present, but they can be circumvented by DOMService if present" \
  'mayscript' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "mayscript" \
  "4_js_mayscript.txt"

  # Node JS stuff
  grepit_search "The use function with a string with a slash at the start is usually the entry point definition for an absolute path" \
  'app.use("/api/", router_1.default);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.use\(\"/" \
  "4_js_node_use_absolut_path.txt"

  grepit_search "The use function is usually the entry point definition for an certain path" \
  'app.use("/api/", router_1.default);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.use\(" \
  "4_js_node_use_generic.txt"

  grepit_search "The get function with a string with a slash at the start is usually the HTTP GET definition for a certain path" \
  'service.get("/");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.get\(\"/" \
  "4_js_node_get_absolut_path.txt"

  grepit_search "The get function is usually the HTTP GET definition for a certain path" \
  'service.get(endpoint.url, endpoint.middleware, micro[endpoint.function].bind(micro));' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\.get\(" \
  "4_js_node_get_generic.txt"

  grepit_search "Electron app setting TLS validation to accept all certificates" \
  'process.env.NODE_TLS_REJECT_UNAUTHORIZED = “0";' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "NODE_TLS_REJECT_UNAUTHORIZED" \
  "3_js_electron_reject_unauthorized.txt"

  grepit_search "Electron app local keyboard shortcuts" \
  'accelerator: process.platform ===' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "accelerator:" \
  "3_js_electron_accelerator_shortcuts.txt"

  grepit_search "Electron app global keyboard shortcuts" \
  'globalShortcut.register("Alt+CommandOrControl+I", () => {' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "globalShortcut\." \
  "3_js_electron_globalShortcut.txt"

  grepit_search "A *lot* of security settings (enabling nodes, XSS to RCE, CSP, etc.) are set by giving them to the BrowserWindow constructor, see https://www.electronjs.org/docs/tutorial/security#1-only-load-secure-content . Also catch obfuscated examples such as o = new k.BrowserWindow(t);" \
  'const mainWindow = new BrowserWindow({webPreferences: {preload: path.join(app.getAppPath(), "preload.js")}}); o = new k.BrowserWindow(t);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "new .{0,${WILDCARD_SHORT}}}BrowserWindow\(" \
  "2_js_electron_BrowserWindow.txt"
}

grepit_module_modsecurity() {
  print_output "[*] Starting Grepit Modsecurity module" "no_log"

  # grepit_search "Block is not recommended to use because it is depending on default action, use deny (or allow)" \
  # 'block' \
  # 'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  # 'block' \
  # "6_modsecurity_block.txt" \
  # "-i"

  grepit_search "Rather complex modsecurity constructs that are worth having a look." \
  'ctl:auditEngine' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ctl:auditEngine' \
  "4_modsecurity_ctl_auditEngine.txt" \
  "-i"

  grepit_search "Rather complex modsecurity constructs that are worth having a look." \
  'ctl:ruleEngine' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ctl:ruleEngine' \
  "4_modsecurity_ctl_ruleEngine.txt" \
  "-i"

  grepit_search "Rather complex modsecurity constructs that are worth having a look." \
  'ctl:ruleRemoveById' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ctl:ruleRemoveById' \
  "4_modsecurity_ctl_ruleRemoveById.txt" \
  "-i"

  grepit_search "Possible command injection when executing bash scripts." \
  'exec:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'exec:' \
  "5_modsecurity_exec.txt" \
  "-i"

  grepit_search "Modsecurity actively changing HTTP response content." \
  'append:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'append:' \
  "5_modsecurity_append.txt" \
  "-i"

  grepit_search "Modsecurity actively changing HTTP response content." \
  'SecContentInjection' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SecContentInjection' \
  "5_modsecurity_SecContentInjection.txt" \
  "-i"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "Modsecurity inspecting uploaded files." \
  '@inspectFile' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '@inspectFile' \
  "5_modsecurity_inspectFile.txt" \
  "-i"

  grepit_search "Modsecurity audit configuration information." \
  'SecAuditEngine' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SecAuditEngine' \
  "5_modsecurity_SecAuditEngine.txt" \
  "-i"

  grepit_search "Modsecurity audit configuration information." \
  'SecAuditLogParts' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SecAuditLogParts' \
  "5_modsecurity_SecAuditLogParts.txt" \
  "-i"
}

grepit_module_mobile_device() {
  print_output "[*] Starting Grepit Mobile device module" "no_log"

  grepit_search "Root detection." \
  'root detection' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "root.{0,${WILDCARD_SHORT}}}detection" \
  "4_mobile_root_detection_root-detection.txt" \
  "-i"

  grepit_search "Root detection." \
  'RootedDevice' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "root.{0,${WILDCARD_SHORT}}}Device" \
  "4_mobile_root_detection_root-device.txt" \
  "-i"

  grepit_search "Root detection." \
  'isRooted' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "is.{0,${WILDCARD_SHORT}}}rooted" \
  "3_mobile_root_detection_isRooted.txt" \
  "-i"

  grepit_search "Root detection." \
  'detect root' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "detect.{0,${WILDCARD_SHORT}}}root" \
  "3_mobile_root_detection_detectRoot.txt" \
  "-i"

  grepit_search "Jailbreak." \
  'jail_break' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "jail.{0,${WILDCARD_SHORT}}}break" \
  "3_mobile_jailbreak.txt" \
  "-i"

  grepit_search "Firebaseio.com links. Depending on how the firebaseio.com database was secured, it might be accessible by opening https://example.firebaseio.com/.json or similar, see https://medium.com/@fs0c131y/how-i-found-the-database-of-the-donald-daters-app-af88b06e39ad" \
  'https://abc-xyz-123.firebaseio.com/' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "https?://.{0,${WILDCARD_SHORT}}}.firebaseio.com" \
  "4_mobile_firebaseio_com.txt" \
  "-i"
}

grepit_module_android() {
  print_output "[*] Starting Grepit Android module" "no_log"
  # For interesting inputs see:
  # http://developer.android.com/training/articles/security-tips.html
  # http://source.android.com/devices/tech/security/

  grepit_search "Dexguard has methods to do temper detection/root detection." \
  'int check = dexguard.util.TamperDetector.checkApk(context);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'TamperDetector' \
  "2_android_dexguar_TamperDetector.txt"

  grepit_search "Dexguard has methods to check if the app was repacked." \
  'int check = dexguard.util.CertificateChecker.checkCertificate(context);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CertificateChecker' \
  "2_android_dexguar_CertificateChecker.txt"

  grepit_search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
  'Log.e(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Log\.e\(' \
  "7_android_logging_error.txt"

  grepit_search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
  'Log.w(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Log\.w\(' \
  "7_android_logging_warning.txt"

  grepit_search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
  'Log.i(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Log\.i\(' \
  "7_android_logging_information.txt"

  grepit_search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
  'Log.d(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Log\.d\(' \
  "7_android_logging_debug.txt"

  grepit_search "From http://developer.android.com/reference/android/util/Log.html : The order in terms of verbosity, from least to most is ERROR, WARN, INFO, DEBUG, VERBOSE. Verbose should never be compiled into an application except during development. Debug logs are compiled in but stripped at runtime. Error, warning and info logs are always kept." \
  'Log.v(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Log\.v\(' \
  "7_android_logging_verbose.txt"

  grepit_search "File MODE_PRIVATE for file access on Android, see https://developer.android.com/reference/android/content/Context.html" \
  'MODE_PRIVATE' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'MODE_PRIVATE' \
  "4_android_access_mode-private.txt"

  grepit_search "File MODE_WORLD_READABLE for file access on Android, see https://developer.android.com/reference/android/content/Context.html" \
  'MODE_WORLD_READABLE' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'MODE_WORLD_READABLE' \
  "1_android_access_mode-world-readable.txt"

  grepit_search "File MODE_WORLD_WRITEABLE for file access on Android, see https://developer.android.com/reference/android/content/Context.html" \
  'MODE_WORLD_WRITEABLE' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'MODE_WORLD_WRITEABLE' \
  "1_android_access_mode-world-writeable.txt"

  grepit_search "Opening files via URI on Android, see https://developer.android.com/reference/android/content/ContentProvider.html#openFile%28android.net.Uri,%20java.lang.String%29" \
  '.openFile(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.openFile\(' \
  "6_android_access_openFile.txt"

  grepit_search "Opening an asset files on Android, see https://developer.android.com/reference/android/content/ContentProvider.html" \
  '.openAssetFile(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.openAssetFile\(' \
  "6_android_access_openAssetFile.txt"

  grepit_search "Android database open or create" \
  '.openOrCreate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.openOrCreate' \
  "6_android_access_openOrCreate.txt"

  grepit_search "Android get database" \
  '.getDatabase(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getDatabase\(' \
  "6_android_access_getDatabase.txt"

  grepit_search "Android open database (and btw. a deprecated W3C standard that was never really implemented in a lot of browsers for JavaScript for local storage)" \
  '.openDatabase(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.openDatabase\(' \
  "6_android_access_openDatabase.txt"

  grepit_search "Get shared preferences on Android, see https://developer.android.com/reference/android/content/SharedPreferences.html" \
  '.getShared' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getShared' \
  "6_android_access_getShared.txt"

  grepit_search "Get cache directory on Android, see https://developer.android.com/reference/android/content/Context.html" \
  'context.getCacheDir()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getCache' \
  "6_android_access_getCache.txt"

  grepit_search "Get code cache directory on Android, see https://developer.android.com/reference/android/content/Context.html" \
  '.getCodeCache' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getCodeCache' \
  "6_android_access_getCodeCache.txt"

  grepit_search "Get external cache directory on Android has no security as it is on the SD card and the file system usually doesn't support permissions, see https://developer.android.com/reference/android/content/Context.html" \
  '.getExternalCacheDirs' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getExternalCache' \
  "6_android_access_getExternalCache.txt"

  grepit_search "Get external file directory on Android has no security as it is on the SD card and the file system usually doesn't support permissions, see https://developer.android.com/reference/android/content/Context.html" \
  '.getExternalFilesDir' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getExternalFile' \
  "6_android_access_getExternalFile.txt"

  grepit_search "Get external media directory on Android has no security as it is on the SD card and the file system usually doesn't support permissions, see https://developer.android.com/reference/android/content/Context.html" \
  '.getExternalMedia' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getExternalMedia' \
  "6_android_access_getExternalMedia.txt"

  grepit_search "Do a query on Android" \
  '.query(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'query\(' \
  "6_android_access_query.txt"

  grepit_search "RawQuery. If the first argument to rawQuery is a user suplied input, it's an SQL injection." \
  'rawQuery(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'rawQuery\(' \
  "4_android_access_rawQuery.txt"

  grepit_search "RawQueryWithFactory. If the second argument to rawQueryWithFactory is a user suplied input, it's an SQL injection." \
  'rawQueryWithFactory(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'rawQueryWithFactory\(' \
  "4_android_access_rawQueryWithFactory.txt"

  grepit_search "Android compile SQL statement" \
  'compileStatement(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'compileStatement\(' \
  "4_android_access_compileStatement.txt"

  grepit_search "Registering receivers and sending broadcasts can be dangerous when exported (which is the case here). See http://resources.infosecinstitute.com/android-hacking-security-part-3-exploiting-broadcast-receivers/" \
  'android:exported=true' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "android:exported.{0,${WILDCARD_SHORT}}}true" \
  "4_android_intents_intent-filter_exported.txt" \
  "-i"

  grepit_search "Registering receivers manually means that every Intent that is sent and matches the specified filter. Can be dangerous. See http://resources.infosecinstitute.com/android-hacking-security-part-3-exploiting-broadcast-receivers/" \
  'registerReceiver(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "registerReceiver\(" \
  "4_android_intents_intent-filter_registerReceiver.txt" \
  "-i"

  grepit_search "Sending broadcasts can be dangerous. See http://resources.infosecinstitute.com/android-hacking-security-part-3-exploiting-broadcast-receivers/" \
  'sendBroadcast(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sendBroadcast\(" \
  "4_android_intents_intent-filter_sendBroadcast.txt" \
  "-i"

  grepit_search "Android startActivity starts another Activity" \
  'startActivity(intent);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'startActivity\(' \
  "5_android_intents_startActivity.txt"

  grepit_search "Android get intent" \
  '.getIntent(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getIntent\(' \
  "5_android_intents_getIntent.txt"

  grepit_search "Android get data from an intent" \
  '.getData(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.getData\(' \
  "5_android_intents_getData.txt"

  grepit_search "Java URI parsing. Often used in Android for an intent, where it is important to specify the receiving package with setPackage as well, so that no other app could receive the intent." \
  'Uri u = Uri.parse(scheme+"://somepath");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Uri.parse\(' \
  "5_android_uri_parse.txt"

  grepit_search "Android set data for an intent. It is important to specify the receiving package with setPackage as well, so that no other app could receive the intent." \
  '.setData(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.setData\(' \
  "5_android_intents_setData.txt"

  grepit_search "Android get info about running processes" \
  'RunningAppProcessInfo' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'RunningAppProcessInfo' \
  "5_android_intents_RunningAppProcessInfo.txt"

  grepit_search "Methods to overwrite SSL certificate checks." \
  'X509TrustManager' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'X509TrustManager' \
  "4_android_ssl_x509TrustManager.txt"

  grepit_search "Insecure hostname verification." \
  'ALLOW_ALL_HOSTNAME_VERIFIER' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ALLOW_ALL_HOSTNAME_VERIFIER' \
  "1_android_ssl_hostname_verifier.txt"

  grepit_search "Implementation of SSL trust settings." \
  'implements TrustStrategy' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'implements TrustStrategy' \
  "4_android_ssl_trustStrategy.txt"

  grepit_search "Android get a key store, eg. to store private key or that include CA certificates used for TLS pinning, etc." \
  'KeyStore' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'KeyStore' \
  "6_android_keyStorage.txt"

  grepit_search "The Key Store provider AndroidKeyStore allows to do hardware-backed storage of Secret Keys (on supported hardware), see https://developer.android.com/training/articles/keystore.html" \
  'KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'AndroidKeyStore' \
  "5_android_AndroidKeyStore.txt"

  grepit_search "Android Hardware-Backed Key Store function to set time until Key is locked again" \
  'setUserAuthenticationValidityDurationSeconds' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'setUserAuthenticationValidityDurationSeconds' \
  "4_android_setUserAuthenticationValidityDurationSeconds.txt"

  grepit_search "Used to query other appps or let them query, see http://developer.android.com/guide/topics/providers/content-provider-basics.html" \
  'ContentResolver' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ContentResolver' \
  "4_android_contentResolver.txt"

  grepit_search "Debuggable webview, see https://developer.chrome.com/devtools/docs/remote-debugging#debugging-webviews" \
  '.setWebContentsDebuggingEnabled(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.setWebContentsDebuggingEnabled\(' \
  "1_android_setWebContentsDebuggingEnabled.txt"

  grepit_search "File system access is often enabled WebViews. Private files could be read by malicious contents. Eg. file://data/data/ch.example/secret.txt" \
  '.loadData(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.loadData\(' \
  "5_android_webview_loadData.txt"

  grepit_search "File system access is often enabled WebViews. Private files could be read by malicious contents. Eg. file://data/data/ch.example/secret.txt" \
  '.loadUrl(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.loadUrl\(' \
  "5_android_webview_loadUrl.txt"

  grepit_search "Changing the security settings of WebViews could allow malicious contents in the WebView to read private data, etc." \
  'setAllowUniversalAccessFromFileURLs' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'setAllowUniversalAccessFromFileURLs' \
  "4_android_webview_setAllowUniversalAccessFromFileURLs.txt"

  grepit_search "Changing the security settings of WebViews could allow malicious contents in the WebView to read private data, etc." \
  'setAllowFileAccess' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'setAllowFileAccess' \
  "4_android_webview_setAllowFileAccess.txt"

  grepit_search "Changing the security settings of WebViews could allow malicious contents in the WebView to read private data, etc." \
  '.setAllow(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\.setAllow\(' \
  "4_android_webview_setAllow.txt"

  grepit_search "Acitivity flagged as new task, might lead to task hijacking: https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf" \
  'intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'FLAG_ACTIVITY_NEW_TASK' \
  "6_android_FLAG_ACTIVITY_NEW_TASK.txt"

  grepit_search "If an Android app wants to specify how the app is backuped, you use BackupAgent to interfere... Often shows which sensitive data is not written to the backup. See https://developer.android.com/reference/android/app/backup/BackupAgent.html" \
  'new BackupAgent()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "BackupAgent" \
  "5_android_backupAgent.txt"

  grepit_search "/system is the path where a lot of binaries are stored. So whenever an Android app does something like executing a binary such as /system/xbin/which with an absolut path. Often used in root-detection mechanisms." \
  '/system/xbin/which' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "/system" \
  "4_android_system_path.txt"

  grepit_search "Often used in root-detection mechanisms." \
  'Superuser.apk' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Superuser.apk" \
  "4_android_superuser_apk.txt" \
  "-i"

  grepit_search "Often used in root-detection mechanisms." \
  'eu.chainfire.supersu' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "supersu" \
  "4_android_supersu.txt"

  grepit_search "Often used in root-detection mechanisms. geprop ro.secure on an adb shell can be used to check. If ro.secure=0, an ADB shell will run commands as the root user on the device. But if ro.secure=1, an ADB shell will run commands as an unprivileged user on the device." \
  'ro.secure' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "ro\.secure" \
  "4_android_ro.secure.txt"

  grepit_search "Often used in root-detection mechanisms, checks if debugger is connected." \
  'android.os.Debug.isDebuggerConnected()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "isDebuggerConnected" \
  "4_android_isDebuggerConnected.txt"

  grepit_search "Probably the singlemost effective root-detection mechanism, implemented by Google itself, SafetyNet. See https://developer.android.com/training/safetynet/index.html and https://koz.io/inside-safetynet/ ." \
  'mGoogleApiClient = new GoogleApiClient.Builder(this).addApi(SafetyNet.API)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SafetyNet" \
  "3_android_SafetyNet.txt"

  grepit_search "Probably the singlemost effective root-detection mechanism, implemented by Google itself, SafetyNet. See https://developer.android.com/training/safetynet/index.html and https://koz.io/inside-safetynet/ ." \
  'public void onResult(SafetyNetApi.AttestationResult result) {' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AttestationResult" \
  "3_android_AttestationResult.txt"
}

grepit_module_ios() {
  print_output "[*] Starting Grepit Apple iOS module" "no_log"

  # Rule triggers for Objective-C and SWIFT
  grepit_search "iOS fileURLWithPath opens a file, eg. for writing. Make sure attributes such as NSURLIsExcludedFromBackupKey described on https://developer.apple.com/library/content/qa/qa1719/_index.html are correctly set." \
  'fileURLWithPath' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'fileURLWithPath' \
  "5_ios_file_access_fileURLWithPath.txt"

  # Rule triggers for Objective-C and SWIFT
  grepit_search "iOS NSURL opens a URL for example a local file, eg. for writing. Make sure attributes such as NSURLIsExcludedFromBackupKey described on https://developer.apple.com/library/content/qa/qa1719/_index.html are correctly set." \
  'NSURL' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSURL' \
  "5_ios_file_access_NSURL.txt"

  grepit_search "iOS NSURLConnection." \
  'NSURLConnection' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSURLConnection' \
  "5_ios_file_access_NSURLConnection.txt"

  grepit_search "iOS NSFile" \
  'NSFile' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSFile' \
  "6_ios_file_access_nsfile.txt"

  grepit_search "iOS writeToFile" \
  'writeToFile' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'writeToFile' \
  "5_ios_file_access_writeToFile.txt"

  grepit_search "iOS writeToUrl" \
  'writeToUrl' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'writeToUrl' \
  "6_ios_writeToUrl.txt"

  grepit_search "iOS UIWebView, see also https://github.com/felixgr/secure-ios-app-dev" \
  'UIWebView' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'UIWebView' \
  "6_ios_UIWebView.txt"

  grepit_search "iOS loadHTMLString method of UIWebView in iOS" \
  'loadHTMLString' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'loadHTMLString' \
  "4_ios_loadHTMLString.txt"

  grepit_search "iOS loadRequest method of UIWebView in iOS" \
  'loadRequest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'loadRequest' \
  "5_ios_loadRequest.txt"

  grepit_search "iOS shouldStartLoadWithRequest method of UIWebView in iOS" \
  'shouldStartLoadWithRequest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'shouldStartLoadWithRequest' \
  "6_ios_shouldStartLoadWithRequest.txt"

  grepit_search "iOS stringByEvaluatingJavaScriptFromString method of UIWebView in iOS" \
  'stringByEvaluatingJavaScriptFromString' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stringByEvaluatingJavaScriptFromString' \
  "4_ios_stringByEvaluatingJavaScriptFromString.txt"

  grepit_search "iOS canAuthenticateAgainstProtectionSpace to authenticate to a server" \
  'canAuthenticateAgainstProtectionSpace' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'canAuthenticateAgainstProtectionSpace' \
  "4_ios_canAuthenticateAgainstProtectionSpace.txt"

  grepit_search "iOS didReceiveAuthenticationChallenge" \
  'didReceiveAuthenticationChallenge' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'didReceiveAuthenticationChallenge' \
  "4_ios_didReceiveAuthenticationChallenge.txt"

  grepit_search "iOS willSendRequestForAuthenticationChallenge" \
  'willSendRequestForAuthenticationChallenge' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'willSendRequestForAuthenticationChallenge' \
  "4_ios_willSendRequestForAuthenticationChallenge.txt"

  grepit_search "iOS continueWithoutCredentialForAuthenticationChallenge" \
  'continueWithoutCredentialForAuthenticationChallenge' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'continueWithoutCredentialForAuthenticationChallenge' \
  "4_ios_continueWithoutCredentialForAuthenticationChallenge.txt"

  grepit_search "iOS ValidatesSecureCertificate" \
  'ValidatesSecureCertificate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ValidatesSecureCertificate' \
  "4_ios_ValidatesSecureCertificate.txt"

  grepit_search "iOS setValidatesSecureCertificate" \
  'setValidatesSecureCertificate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'setValidatesSecureCertificate' \
  "4_ios_setValidatesSecureCertificate.txt"

  grepit_search "iOS setAllowsAnyHTTPSCertificate is a private API and will therefore be rejected when submitted to the Apple Store, nevertheless interesting to see if it is present" \
  'setAllowsAnyHTTPSCertificate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'setAllowsAnyHTTPSCertificate' \
  "4_ios_setAllowsAnyHTTPSCertificate.txt"

  grepit_search "iOS NSHTTPCookieAcceptPolicy method of UIWebView in iOS, NSHTTPCookieAcceptPolicyNever or NSHTTPCookieAcceptPolicyOnlyFromMainDocumentDomain" \
  'NSHTTPCookieAcceptPolicy' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSHTTPCookieAcceptPolicy' \
  "4_ios_NSHTTPCookieAcceptPolicy.txt"

  grepit_search "iOS File protection APIs, NSFileProtectionKey, NSFileProtectionNone, NSFileProtectionComplete, NSFileProtectionCompleteUnlessOpen, NSFileProtectionCompleteUntilFirstUserAuthentication." \
  'NSFileProtection' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSFileProtection' \
  "4_ios_file_access_nsfileprotection.txt"

  grepit_search "iOS File protection APIs" \
  'NSFileManager' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSFileManager' \
  "5_ios_file_access_nsfilemanager.txt"

  grepit_search "iOS File protection APIs" \
  'NSPersistantStoreCoordinator' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSPersistantStoreCoordinator' \
  "5_ios_file_access_nspersistantstorecoordinator.txt"

  grepit_search "iOS File protection APIs, NSDataWritingFileProtectionNone, NSDataWritingFileProtectionComplete, NSDataWritingFileProtectionCompleteUnlessOpen, NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication" \
  'NSDataWritingFileProtectionNone' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSData' \
  "6_ios_file_access_nsdata.txt"

  # The following regex match if it is not a "T" that would indicate the "ThisDeviceOnly" part
  grepit_search "iOS Keychain kSecAttrAccessibleWhenUnlocked should be kSecAttrAccessibleWhenUnlockedThisDeviceOnly to make sure they are not backuped, see https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked" \
  'kSecAttrAccessibleWhenUnlocked and something afterwards' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecAttrAccessibleWhenUnlocked[^T]' \
  "3_ios_keychain_kSecAttrAccessibleWhenUnlocked.txt"

  grepit_search "iOS Keychain kSecAttrAccessibleAfterFirstUnlock should be kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly to make sure they are not backuped, see https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked" \
  'kSecAttrAccessibleAfterFirstUnlock and something afterwards' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecAttrAccessibleAfterFirstUnlock[^T]' \
  "3_ios_keychain_kSecAttrAccessibleAfterFirstUnlock.txt"

  grepit_search "iOS Keychain kSecAttrAccessibleWhenPasscodeSet should be kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly to make sure they are not backuped, see https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked" \
  'kSecAttrAccessibleWhenPasscodeSet and something afterwards' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecAttrAccessibleWhenPasscodeSet[^T]' \
  "3_ios_keychain_kSecAttrAccessibleWhenPasscodeSet.txt"

  grepit_search "iOS Keychain kSecAttrAccessibleAlways should be kSecAttrAccessibleAlwaysThisDeviceOnly to make sure they are not backuped, see https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlocked" \
  'kSecAttrAccessibleAlways and something afterwards' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecAttrAccessibleAlways[^T]' \
  "3_ios_keychain_kSecAttrAccessibleAlways.txt"

  grepit_search "iOS Keychain kSecAttrSynchronizable should be false, see https://github.com/felixgr/secure-ios-app-dev" \
  'kSecAttrSynchronizable' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecAttrSynchronizable' \
  "3_ios_keychain_kSecAttrSynchronizable.txt"

  grepit_search "iOS Keychain kSecAttrTokenIDSecureEnclave should be set so that private keys are non-exportable in the Secure Enclave, see https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave" \
  'kSecAttrTokenIDSecureEnclave' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecAttrTokenIDSecureEnclave' \
  "3_ios_keychain_kSecAttrTokenIDSecureEnclave.txt"

  grepit_search "iOS Keychain stuff, general match" \
  'kSecAttrAccessible' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecAttrAccessible' \
  "4_ios_keychain_ksecattraccessible.txt"

  grepit_search "iOS Keychain stuff" \
  'SecItemAdd' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SecItemAdd' \
  "4_ios_keychain_secitemadd.txt"

  grepit_search "iOS Keychain stuff" \
  'SecItemUpdate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SecItemUpdate' \
  "5_ios_keychain_SecItemUpdate.txt"

  grepit_search "iOS Keychain stuff" \
  'SecItemCopyMatching' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SecItemCopyMatching' \
  "5_ios_keychain_SecItemCopyMatching.txt"

  grepit_search "iOS Keychain stuff" \
  'KeychainItemWrapper' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'KeychainItemWrapper' \
  "5_ios_keychain_KeychainItemWrapper.txt"

  grepit_search "iOS Keychain stuff" \
  'Security.h' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Security\.h' \
  "6_ios_keychain_security_h.txt"

  grepit_search "CFStream" \
  'CFStream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFStream' \
  "6_ios_CFStream.txt"

  grepit_search "kCFStreamSSLAllowsExpiredCertificates" \
  'kCFStreamSSLAllowsExpiredCertificates' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kCFStreamSSLAllowsExpiredCertificates' \
  "3_ios_kCFStreamSSLAllowsExpiredCertificates.txt"

  grepit_search "kCFStreamSSLAllowsExpiredRoots" \
  'kCFStreamSSLAllowsExpiredRoots' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kCFStreamSSLAllowsExpiredRoots' \
  "3_ios_kCFStreamSSLAllowsExpiredRoots.txt"

  grepit_search "kCFStreamSSLAllowsAnyRoot" \
  'kCFStreamSSLAllowsAnyRoot' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kCFStreamSSLAllowsAnyRoot' \
  "3_ios_kCFStreamSSLAllowsAnyRoot.txt"

  grepit_search "kCFStreamSSLValidatesCertificateChain" \
  'kCFStreamSSLValidatesCertificateChain' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kCFStreamSSLValidatesCertificateChain' \
  "3_ios_kCFStreamSSLValidatesCertificateChain.txt"

  grepit_search "kCFStreamPropertySSLSettings" \
  'kCFStreamPropertySSLSettings' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kCFStreamPropertySSLSettings' \
  "4_ios_kCFStreamPropertySSLSettings.txt"

  grepit_search "kCFStreamSSLPeerName" \
  'kCFStreamSSLPeerName' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kCFStreamSSLPeerName' \
  "4_ios_kCFStreamSSLPeerName.txt"

  grepit_search "kSecTrustOptionAllowExpired" \
  'kSecTrustOptionAllowExpired' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecTrustOptionAllowExpired' \
  "3_ios_kSecTrustOptionAllowExpired.txt"

  grepit_search "kSecTrustOptionAllowExpiredRoot" \
  'kSecTrustOptionAllowExpiredRoot' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecTrustOptionAllowExpiredRoot' \
  "3_ios_kSecTrustOptionAllowExpiredRoot.txt"

  grepit_search "kSecTrustOptionImplicitAnchors" \
  'kSecTrustOptionImplicitAnchors' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kSecTrustOptionImplicitAnchors' \
  "4_ios_kSecTrustOptionImplicitAnchors.txt"

  grepit_search "NSStreamSocketSecurityLevel" \
  'NSStreamSocketSecurityLevel' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSStreamSocketSecurityLevel' \
  "4_ios_NSStreamSocketSecurityLevel.txt"

  grepit_search "NSCachedURLResponse willCacheResponse" \
  'willCacheResponse' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'willCacheResponse' \
  "5_ios_willCacheResponse.txt"

  grepit_search "CFFTPStream" \
  'CFFTPStream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFFTPStream' \
  "5_ios_CFFTPStream.txt"

  grepit_search "NSStreamin" \
  'NSStreamin' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSStreamin' \
  "5_ios_NSStreamin.txt"

  grepit_search "NSXMLParser" \
  'NSXMLParser' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSXMLParser' \
  "5_ios_NSXMLParser.txt"

  grepit_search "UIPasteboardNameGeneral and UIPasteboardNameFind" \
  'UIPasteboardName' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'UIPasteboardName' \
  "5_ios_UIPasteboardName.txt"

  grepit_search "CFHTTP" \
  'CFHTTP' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFHTTP' \
  "6_ios_CFHTTP.txt"

  grepit_search "CFNetServices" \
  'CFNetServices' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFNetServices' \
  "6_ios_CFNetServices.txt"

  grepit_search "FTPURL" \
  'FTPURL' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'FTPURL' \
  "5_ios_FTPURL.txt"

  grepit_search "IOBluetooth" \
  'IOBluetooth' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'IOBluetooth' \
  "5_ios_IOBluetooth.txt"

  grepit_search "NSLog" \
  'NSLog(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSLog\(' \
  "7_ios_NSLog.txt"

  grepit_search "iOS string format function initWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'initWithFormat:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'initWithFormat:' \
  "6_ios_string_format_initWithFormat_wide.txt"

  grepit_search "iOS string format function initWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'initWithFormat:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'initWithFormat:[^@]' \
  "5_ios_string_format_initWithFormat_narrow.txt"

  grepit_search "iOS string format function informativeTextWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'informativeTextWithFormat:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'informativeTextWithFormat:' \
  "6_ios_string_format_informativeTextWithFormat_wide.txt"

  grepit_search "iOS string format function informativeTextWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'informativeTextWithFormat:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'informativeTextWithFormat:[^@]' \
  "5_ios_string_format_informativeTextWithFormat_narrow.txt"

  grepit_search "iOS string format function format. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'format:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'format:' \
  "6_ios_string_format_format_wide.txt"

  grepit_search "iOS string format function format. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'format:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'format:[^@]' \
  "5_ios_string_format_format_narrow.txt"

  grepit_search "iOS string format function stringWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'stringWithFormat:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stringWithFormat:' \
  "6_ios_string_format_stringWithFormat_wide.txt"

  grepit_search "iOS string format function stringWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'stringWithFormat:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stringWithFormat:[^@]' \
  "5_ios_string_format_stringWithFormat_narrow.txt"

  grepit_search "iOS string format function stringByAppendingFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'stringByAppendingFormat:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stringByAppendingFormat:' \
  "6_ios_string_format_stringByAppendingFormat_wide.txt"

  grepit_search "iOS string format function stringByAppendingFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'stringByAppendingFormat:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stringByAppendingFormat:[^@]' \
  "5_ios_string_format_stringByAppendingFormat_narrow.txt"

  grepit_search "iOS string format function appendFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'appendFormat:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'appendFormat:' \
  "6_ios_string_format_appendFormat_wide.txt"

  grepit_search "iOS string format function appendFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'appendFormat:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'appendFormat:[^@]' \
  "5_ios_string_format_appendFormat_narrow.txt"

  grepit_search "iOS string format function alertWithMessageText. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'alertWithMessageText:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'alertWithMessageText:' \
  "6_ios_string_format_alertWithMessageText_wide.txt"

  grepit_search "iOS string format function alertWithMessageText. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'alertWithMessageText:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'alertWithMessageText:[^@]' \
  "5_ios_string_format_alertWithMessageText_narrow.txt"

  grepit_search "iOS string format function predicateWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'predicateWithFormat:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'predicateWithFormat:' \
  "6_ios_string_format_predicateWithFormat_wide.txt"

  grepit_search "iOS string format function predicateWithFormat. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'predicateWithFormat:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'predicateWithFormat:[^@]' \
  "5_ios_string_format_predicateWithFormat_narrow.txt"

  grepit_search "iOS string format function of NSException. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  '[NSException raise:format:]' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ':format' \
  "6_ios_string_format.txt"

  grepit_search "iOS string format function NSRunAlertPanel. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'NSRunAlertPanel:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSRunAlertPanel:' \
  "6_ios_string_format_NSRunAlertPanel_wide.txt"

  grepit_search "iOS string format function NSRunAlertPanel. Just check if the first argument to these functions are user controlled, that could be a format string vulnerability." \
  'NSRunAlertPanel:var' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSRunAlertPanel:[^@]' \
  "5_ios_string_format_NSRunAlertPanel_narrow.txt"

  grepit_search "iOS URL handler handleOpenURL, also see https://github.com/felixgr/secure-ios-app-dev" \
  'handleOpenURL' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'handleOpenURL' \
  "6_ios_string_format_url_handler_handleOpenURL.txt"

  grepit_search "iOS URL handler openURL" \
  'openURL' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'openURL' \
  "6_ios_string_format_url_handler_openURL.txt"

  grepit_search "sourceApplication is a parameter used in the application method used for custom URL handling and receiving data from another app, see https://developer.apple.com/documentation/uikit/uiapplicationdelegate/1623073-application . See also https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html ." \
  'sourceApplication:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sourceApplication:' \
  "4_ios_sourceApplication.txt"

  # Below here Info.plist stuff
  grepit_search "NSAllowsArbitraryLoads set to 1 allows iOS applications to load resources over insecure non-TLS protocols and is specified in the Info.plist file. It doesn't mean the application is really doing it, however, it is recommended to disable non-TLS connections." \
  'NSAllowsArbitraryLoads' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSAllowsArbitraryLoads' \
  "3_ios_NSAllowsArbitraryLoads.txt"

  grepit_search "CFBundleDocumentTypes defines in the Info.plist file what kind of documents can be opened with this application, example of such a handler can be found here: https://stackoverflow.com/questions/2774343/how-do-i-associate-file-types-with-an-iphone-application#2781290 . See also https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html ." \
  'CFBundleDocumentTypes' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFBundleDocumentTypes' \
  "5_ios_CFBundleDocumentTypes.txt"

  grepit_search "CFBundleURLTypes defines int he Info.plist file a custom URL handler that will trigger the application and is used as an IPC mechanism. See also https://developer.apple.com/library/content/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/Inter-AppCommunication/Inter-AppCommunication.html ." \
  'CFBundleURLTypes' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFBundleURLTypes' \
  "5_ios_CFBundleURLTypes.txt"

  grepit_search "SecRandomCopyBytes cryptographic secure random number, see also https://github.com/felixgr/secure-ios-app-dev" \
  'int r = SecRandomCopyBytes(kSecRandomDefault, sizeof(int), (uint8_t*) &res);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SecRandomCopyBytes' \
  "4_ios_SecRandomCopyBytes.txt"

  grepit_search "allowScreenShot, see also https://github.com/felixgr/secure-ios-app-dev" \
  'allowScreenShot' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'allowScreenShot' \
  "4_ios_allowScreenShot.txt"

  grepit_search "UIPasteboardNameGeneral, see also https://github.com/felixgr/secure-ios-app-dev" \
  'UIPasteboardNameGeneral' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'UIPasteboardNameGeneral' \
  "4_ios_UIPasteboardNameGeneral.txt"

  grepit_search "secureTextEntry, see also https://github.com/felixgr/secure-ios-app-dev" \
  'secureTextEntry' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'secureTextEntry' \
  "4_ios_secureTextEntry.txt"

  grepit_search "NSCoding, see also https://github.com/felixgr/secure-ios-app-dev" \
  'NSCoding' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSCoding' \
  "6_ios_NSCoding.txt"

  grepit_search "Other deserialization (CFBundle, NSBundle, NSKeyedUnarchiverDelegate, didDecodeObject, awakeAfterUsingCoder) can directly lead to code execution by returning different objects during deserialization. See also https://github.com/felixgr/secure-ios-app-dev" \
  'CFBundle' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFBundle' \
  "6_ios_CFBundle.txt"

  grepit_search "Other deserialization (CFBundle, NSBundle, NSKeyedUnarchiverDelegate, didDecodeObject, awakeAfterUsingCoder) can directly lead to code execution by returning different objects during deserialization. See also https://github.com/felixgr/secure-ios-app-dev" \
  'NSBundle' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSBundle' \
  "6_ios_NSBundle.txt"

  grepit_search "Other deserialization (CFBundle, NSBundle, NSKeyedUnarchiverDelegate, didDecodeObject, awakeAfterUsingCoder) can directly lead to code execution by returning different objects during deserialization. See also https://github.com/felixgr/secure-ios-app-dev" \
  'NSKeyedUnarchiverDelegate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSKeyedUnarchiverDelegate' \
  "6_ios_NSKeyedUnarchiverDelegate.txt"

  grepit_search "Other deserialization (CFBundle, NSBundle, NSKeyedUnarchiverDelegate, didDecodeObject, awakeAfterUsingCoder) can directly lead to code execution by returning different objects during deserialization. See also https://github.com/felixgr/secure-ios-app-dev" \
  'didDecodeObject' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'didDecodeObject' \
  "6_ios_didDecodeObject.txt"

  grepit_search "Other deserialization (CFBundle, NSBundle, NSKeyedUnarchiverDelegate, didDecodeObject, awakeAfterUsingCoder) can directly lead to code execution by returning different objects during deserialization. See also https://github.com/felixgr/secure-ios-app-dev" \
  'awakeAfterUsingCoder' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'awakeAfterUsingCoder' \
  "6_ios_awakeAfterUsingCoder.txt"

  grepit_search "Check for SQL injection. See also https://github.com/felixgr/secure-ios-app-dev" \
  'sqlite3_exec()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sqlite3_exec\(' \
  "4_ios_sqlite3_exec.txt"

  grepit_search "Check for SQL injection. See also https://github.com/felixgr/secure-ios-app-dev" \
  'sqlite3_prepare' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sqlite3_prepare' \
  "5_ios_sqlite3_prepare.txt"

  grepit_search "libsqlite3.dylib in iOS supports fts3_tokenizer function, which has two security issues by design. See also https://github.com/felixgr/secure-ios-app-dev" \
  'fts3_tokenizer' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'fts3_tokenizer' \
  "3_ios_fts3_tokenizer.txt"

  grepit_search "allowedInsecureSchemes, see also https://github.com/felixgr/secure-ios-app-dev" \
  'allowedInsecureSchemes' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'allowedInsecureSchemes' \
  "4_ios_allowedInsecureSchemes.txt"

  grepit_search "allowLocalhostRequest, see also https://github.com/felixgr/secure-ios-app-dev" \
  'allowLocalhostRequest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'allowLocalhostRequest' \
  "3_ios_allowLocalhostRequest.txt"

  grepit_search "GTM_ALLOW_INSECURE_REQUESTS, see also https://github.com/felixgr/secure-ios-app-dev" \
  'GTM_ALLOW_INSECURE_REQUESTS' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'GTM_ALLOW_INSECURE_REQUESTS' \
  "3_ios_GTM_ALLOW_INSECURE_REQUESTS.txt"

  grepit_search "registerForRemoteNotificationTypes, see also https://github.com/felixgr/secure-ios-app-dev" \
  'registerForRemoteNotificationTypes' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'registerForRemoteNotificationTypes' \
  "3_ios_registerForRemoteNotificationTypes.txt"

  grepit_search "CFDataRef might lead to memory corruption issues when incorrectly converted from/to C string, see also https://github.com/felixgr/secure-ios-app-dev" \
  'CFDataRef' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFDataRef' \
  "5_ios_CFDataRef.txt"

  grepit_search "CFStringRef might lead to memory corruption issues when incorrectly converted from/to C string, see also https://github.com/felixgr/secure-ios-app-dev" \
  'CFStringRef' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFStringRef' \
  "5_ios_CFStringRef.txt"

  grepit_search "NSString might lead to memory corruption issues when incorrectly converted from/to C string, see also https://github.com/felixgr/secure-ios-app-dev" \
  'NSString' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NSString' \
  "5_ios_NSString.txt"

  grepit_search "Format string vulnerable syslog method, see also https://github.com/felixgr/secure-ios-app-dev" \
  'syslog(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'syslog\(' \
  "4_ios_syslog.txt"

  grepit_search "Format string vulnerable CFStringCreateWithFormat method, see also https://github.com/felixgr/secure-ios-app-dev" \
  'CFStringCreateWithFormat' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFStringCreateWithFormat' \
  "3_ios_CFStringCreateWithFormat.txt"

  grepit_search "Format string vulnerable CFStringAppendFormat method, see also https://github.com/felixgr/secure-ios-app-dev" \
  'CFStringAppendFormat' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CFStringAppendFormat' \
  "5_ios_CFStringAppendFormat.txt"

  grepit_search "UnsafePointer for Swift methods, see also https://github.com/felixgr/secure-ios-app-dev can lead to memory corruption, see also https://books.google.ch/books?id=RbaiDQAAQBAJ&pg=PA29&lpg=PA29&dq=UnsafePointer+memory+corruption&source=bl&ots=FPmKgC20rD&sig=ACfU3U0BG-I61OcUU2o_hzzDWCt4GtCexA&hl=en&sa=X&ved=2ahUKEwiv1aars6jnAhVU6qYKHRMiAjUQ6AEwAHoECAoQAQ#v=onepage&q=UnsafePointer%20memory%20corruption&f=false" \
  'UnsafePointer' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'UnsafePointer' \
  "4_ios_UnsafePointer.txt"

  grepit_search "UnsafeMutablePointer for Swift methods, see also https://github.com/felixgr/secure-ios-app-dev" \
  'UnsafeMutablePointer' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'UnsafeMutablePointer' \
  "4_ios_UnsafeMutablePointer.txt"

  grepit_search "UnsafeCollection for Swift methods, see also https://github.com/felixgr/secure-ios-app-dev" \
  'UnsafeCollection' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'UnsafeCollection' \
  "4_ios_UnsafeCollection.txt"
}

grepit_module_python() {
  print_output "[*] Starting Grepit Python module" "no_log"

  # Python language specific stuff
  # - whitespaces are allowed between function names and brackets: abs (-1.3)
  # - Function names are case sensitive
  # - Due to the many flexible way of calling a function, the regexes will only catch "the most natural" case

  grepit_search "Input function in Python 2.X is dangerous (but not in python 3.X), as it read from stdin and then evals the input, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'input()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "input\s{0,${WILDCARD_SHORT}}\(" \
  "4_python_input_function.txt"

  grepit_search "Assert statements are not compiled into the optimized byte code, therefore can not be used for security purposes, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'assert variable and other' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "assert\s{1,${WILDCARD_SHORT}}" \
  "4_python_assert_statement.txt"

  grepit_search "The 'is' object identity operator should not be used for numbers, see https://access.redhat.com/blogs/766093/posts/2592591" \
  '1+1 is 2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\d\s{1,${WILDCARD_SHORT}}is\s{1,${WILDCARD_SHORT}}" \
  "5_python_is_object_identity_operator_left.txt"

  grepit_search "The 'is' object identity operator should not be used for numbers, see https://access.redhat.com/blogs/766093/posts/2592591" \
  '1+1 is 2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\s{1,${WILDCARD_SHORT}}is\s{1,${WILDCARD_SHORT}}\d" \
  "5_python_is_object_identity_operator_right.txt"

  # grepit_search "The 'is' object identity operator should not be used for numbers, see https://access.redhat.com/blogs/766093/posts/2592591" \
  # 'object.an_integer is other_object.other_integer' \
  # 'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  # "\sis\s" \
  # "5_python_is_object_identity_operator_general.txt"

  grepit_search "The float type can not be reliably compared for equality, see https://access.redhat.com/blogs/766093/posts/2592591" \
  '2.2 * 3.0 == 3.3 * 2.2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\d\.\d{1,${WILDCARD_SHORT}}\s{1,${WILDCARD_SHORT}}==\s{1,${WILDCARD_SHORT}}" \
  "4_python_float_equality_left.txt"

  grepit_search "The float type can not be reliably compared for equality, see https://access.redhat.com/blogs/766093/posts/2592591" \
  '2.2 * 3.0 == 3.3 * 2.2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\s{1,${WILDCARD_SHORT}}==\s{1,${WILDCARD_SHORT}}\d\.\d{1,${WILDCARD_SHORT}}" \
  "4_python_float_equality_right.txt"

  grepit_search "The float type can not be reliably compared for equality. Make sure none of these comparisons uses floats, see https://access.redhat.com/blogs/766093/posts/2592591" \
  '2.2 * 3.0 == 3.3 * 2.2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\s{1,${WILDCARD_SHORT}}==\s{1,${WILDCARD_SHORT}}" \
  "4_python_float_equality_general.txt"

  grepit_search "Double underscore variable visibility can be tricky, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'self.__private' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "self\.__" \
  "4_python_double_underscore_general.txt"

  grepit_search "Doing things with __code__ is very low level" \
  'object.__code__' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "__code__" \
  "4_python_double_underscore_code.txt"

  grepit_search "The shell=True named argument of the subprocess module makes command injection possible, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'subprocess.call(unvalidated_input, shell=True)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "shell=True" \
  "3_python_subprocess_shell_true.txt"

  grepit_search "mktemp of the tempfile module is flawed, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'tempfile.mktemp()' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "mktemp\s{0,${WILDCARD_SHORT}}\(" \
  "4_python_tempfile_mktemp.txt"

  grepit_search "shutil.copyfile is flawed as it creates the destination in the most insecure manner possible, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'shutil.copyfile(src, dst)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "copyfile\s{0,${WILDCARD_SHORT}}\(" \
  "3_python_shutil_copyfile.txt"

  grepit_search "shutil.move is flawed and silently leaves the old file behind if the source and destination are on different file systems, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'shutil.move(src, dst)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "move\s{0,${WILDCARD_SHORT}}\(" \
  "4_python_shutil_move.txt"

  grepit_search "yaml.load is flawed and uses pickle to deserialize its data, which leads to code execution, see https://access.redhat.com/blogs/766093/posts/2592591 . The proper way is to use safe_load." \
  'import yaml' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "import\s{0,${WILDCARD_SHORT}}yaml" \
  "4_python_yaml_import.txt"

  grepit_search "pickle leads to code execution if untrusted input is deserialized, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'import pickle' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "import\s{0,${WILDCARD_SHORT}}pickle" \
  "4_python_pickle_import.txt"

  grepit_search "pickle leads to code execution if untrusted input is deserialized, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'from pickle' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "from\s{0,${WILDCARD_SHORT}}pickle" \
  "4_python_pickle_from.txt"

  grepit_search "shelve leads to code execution if untrusted input is deserialized, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'import shelve' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "import\s{0,${WILDCARD_SHORT}}shelve" \
  "4_python_shelve_import.txt"

  grepit_search "shelve leads to code execution if untrusted input is deserialized, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'from shelve' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "from\s{0,${WILDCARD_SHORT}}shelve" \
  "4_python_shelve_from.txt"

  grepit_search "jinja2 in its default configuration leads to XSS if untrusted input is used for rendering, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'import jinja2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "import\s{0,${WILDCARD_SHORT}}jinja2" \
  "4_python_jinja2_import.txt"

  grepit_search "jinja2 in its default configuration leads to XSS if untrusted input is used for rendering, see https://access.redhat.com/blogs/766093/posts/2592591" \
  'from jinja2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "from\s{0,${WILDCARD_SHORT}}jinja2" \
  "4_python_jinja2_from.txt"

  grepit_search "RSA key generation, don't choose weak e primitive, see https://blog.trailofbits.com/2019/07/08/fuck-rsa/" \
  'RSA.gen_key(keysize, 1, callback=lambda x, y, z: None)' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "gen_key\(" \
  "4_python_gen_key.txt"

  grepit_search "Using python pip's extra-index-url can lead to depdency injection, see https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610" \
  '--extra-index-url' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "extra-index-url" \
  "2_python_extra_index_url.txt"
}

grepit_module_ruby() {
  print_output "[*] Starting Grepit Ruby module" "no_log"

  # ruby is case sensitive in general
  # If you have a ruby application, the static analyzer https://github.com/presidentbeef/brakeman seems pretty promising

  grepit_search "Basic authentication in ruby with http_basic_authenticate_with" \
  'http_basic_authenticate_with' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "http_basic_authenticate_with" \
  "3_ruby_http_basic_authenticate_with.txt"

  grepit_search "Content tag can lead to XSS, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_content_tag.rb" \
  'content_tag :tag, body' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "content_tag" \
  "4_ruby_content_tag.txt"

  grepit_search "Possible deserialization issues, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_deserialize.rb" \
  ':YAML' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":YAML" \
  "3_ruby_yaml.txt"

  grepit_search "Possible deserialization issues, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_deserialize.rb" \
  ':load' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":load" \
  "3_ruby_load.txt"

  grepit_search "Possible deserialization issues, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_deserialize.rb" \
  ':load_documents' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":load_documents" \
  "3_ruby_load_documents.txt"

  grepit_search "Possible deserialization issues, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_deserialize.rb" \
  ':load_stream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":load_stream" \
  "3_ruby_load_stream.txt"

  grepit_search "Possible deserialization issues, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_deserialize.rb" \
  ':parse_documents' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":parse_documents" \
  "3_ruby_parse_documents.txt"

  grepit_search "Possible deserialization issues, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_deserialize.rb" \
  ':parse_stream' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":parse_stream" \
  "3_ruby_parse_stream.txt"

  grepit_search "Detailed exceptions shown, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_detailed_exceptions.rb" \
  ':show_detailed_exceptions' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":show_detailed_exceptions" \
  "3_ruby_show_detailed_exceptions.txt"

  grepit_search "Spawning a subshell? See https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_execute.rb" \
  ':capture2e' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":capture" \
  "3_ruby_capture.txt"

  grepit_search "XSRF protection in ruby. See http://api.rubyonrails.org/classes/ActionController/RequestForgeryProtection/ClassMethods.html" \
  'protect_from_forgery' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "protect_from_forgery" \
  "3_ruby_protect_from_forgery.txt"

  grepit_search "HTTP redirects in ruby. See https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_redirect.rb" \
  ':redirect_to' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ":redirect_to" \
  "3_ruby_redirect_to.txt"

  grepit_search "Authenticity token verficiation skipped? See https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_skip_before_filter.rb" \
  'verify_authenticity_token' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "verify_authenticity_token" \
  "3_ruby_verify_authenticity_token.txt"

  grepit_search "Regex function that allows anything after a newline, \\A and \\z has to be used in regex to prevent this, see https://github.com/presidentbeef/brakeman/blob/master/lib/brakeman/checks/check_validation_regex.rb" \
  'validates_format_of' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "validates_format_of" \
  "3_ruby_validates_format_of.txt"
}

grepit_module_azure() {
  print_output "[*] Starting Grepit Azure Cloud module" "no_log"

  grepit_search "Azure has an Azure Resource Manager PowerShell cmdlet to store credentials in a JSON file. TokenCache is one of the keywords." \
  'TokenCache' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TokenCache" \
  "3_azure_TokenCache.txt"

  grepit_search "Azure has an Azure Resource Manager PowerShell cmdlet to store credentials in a JSON file. PublishSettingsFileUrl is one of the keywords." \
  'PublishSettingsFileUrl' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "PublishSettingsFileUrl" \
  "3_azure_PublishSettingsFileUrl.txt"

  grepit_search "Azure has an Azure Resource Manager PowerShell cmdlet to store credentials in a JSON file. ManagementPortalUrl is one of the keywords." \
  'ManagementPortalUrl' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "ManagementPortalUrl" \
  "3_azure_ManagementPortalUrl.txt"
}

grepit_module_c_lang() {
  print_output "[*] Starting Grepit C language module" "no_log"

  grepit_search "malloc. Rather rare bug, but see issues CVE-2010-0041 and CVE-2010-0042. Uninitialized memory access issues? Could also happen in java/android native code. Also developers should check return codes." \
  'malloc(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'malloc\(' \
  "5_c_malloc.txt"

  grepit_search "realloc. Rather rare bug, but see issues CVE-2010-0041 and CVE-2010-0042. Uninitialized memory access issues? Could also happen in java/android native code. Also developers should check return codes." \
  'realloc(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'realloc\(' \
  "5_c_realloc.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: memcpy" \
  'memcpy(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'memcpy\(' \
  "2_c_insecure_c_functions_memcpy.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: memset" \
  'memset(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'memset\(' \
  "2_c_insecure_c_functions_memset.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: strcat --> strlcat, strncat --> strlcat" \
  'strcat(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'strcat\(' \
  "2_c_insecure_c_functions_strcat.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: strcat --> strlcat, strncat --> strlcat" \
  'strncat(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'strncat\(' \
  "5_c_insecure_c_functions_strncat.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: strcpy --> strlcpy" \
  'strcpy(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'strcpy\(' \
  "2_c_insecure_c_functions_strcpy.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: strcpy --> strlcpy" \
  'strncpy(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'strncpy\(' \
  "5_c_insecure_c_functions_strncpy.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: sprintf --> snprintf, vsprintf --> vsnprintf" \
  'sprintf(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sprintf\(' \
  "2_c_insecure_c_functions_sprintf_snprintf.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: sprintf --> snprintf, vsprintf --> vsnprintf" \
  'snprintf(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'snprintf\(' \
  "5_c_insecure_c_functions_sprintf_snprintf.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: fprintf --> fnprintf" \
  'fprintf(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'fprintf\(' \
  "3_c_insecure_c_functions_fprintf.txt"

  grepit_search "Format string vulnerable methods: fprintf --> fnprintf, where the second argument (string format) is not a constant string but a variable name" \
  'fprintf(foobar, bazbar, lalal);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "fprintf\([^,]{2,${WILDCARD_SHORT}}, {0,${WILDCARD_SHORT}}[^\"']{2,2}" \
  "2_c_insecure_c_functions_fprintf_no_constant.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: fprintf --> fnprintf" \
  'fnprintf(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'fnprintf\(' \
  "5_c_insecure_c_functions_fnprintf.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: The format string should never be simple %s but rather %9s or similar to limit size that is read." \
  'scanf(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'scanf\(' \
  "2_c_insecure_c_functions_scanf.txt"

  grepit_search "Buffer overflows and format string vulnerable methods: gets --> fgets" \
  'gets(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'gets\(' \
  "5_c_insecure_c_functions_gets.txt"

  grepit_search "Random is not a secure random number generator" \
  'random(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'random\(' \
  "5_c_random.txt"
}

grepit_module_malware() {
  print_output "[*] Starting Grepit Malware module" "no_log"

  grepit_search "Viagra search" \
  'viagra' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'viagra' \
  "5_malware_viagra.txt" \
  "-i"

  grepit_search "Potenzmittel is the German word mostly used for viagra" \
  'potenzmittel' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'potenzmittel' \
  "5_malware_potenzmittel.txt" \
  "-i"

  grepit_search "Pharmacy" \
  'pharmacy' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'pharmacy' \
  "5_malware_pharmacy.txt" \
  "-i"

  grepit_search "Drug" \
  'drug' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'drug' \
  "5_malware_drug.txt" \
  "-i"
}

grepit_module_crypto_creds() {
  print_output "[*] Starting Grepit Crypto and Credential module" "no_log"

  grepit_search "Crypt (the method itself) can be dangerous, also matches any calls to decrypt(, encrypt( or whatevercrypt(, which is desired" \
  'crypt(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'crypt\(' \
  "4_cryptocred_crypt_call.txt" \
  "-i"

  grepit_search "Rot32 is really really bad obfuscation and has nothing to do with crypto." \
  'ROT32' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ROT32' \
  "4_cryptocred_ciphers_rot32.txt" \
  "-i"

  grepit_search "RC2 cipher. Security depends heavily on usage and what is secured." \
  'RC2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'RC2' \
  "5_cryptocred_ciphers_rc2.txt" \
  "-i"

  grepit_search "RC4 cipher. Security depends heavily on usage and what is secured." \
  'RC4' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'RC4' \
  "5_cryptocred_ciphers_rc4.txt"

  grepit_search "CRC32 is a checksum algorithm. Security depends heavily on usage and what is secured." \
  'CRC32' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'CRC32' \
  "4_cryptocred_ciphers_crc32.txt" \
  "-i"

  grepit_search "DES cipher. Security depends heavily on usage and what is secured." \
  'DES' \
  'DESCRIPTION TRADES' \
  'DES' \
  "7_cryptocred_ciphers_des.txt"

  grepit_search "MD2. Security depends heavily on usage and what is secured." \
  'MD2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'MD2' \
  "5_cryptocred_ciphers_md2.txt"

  grepit_search "MD5. Security depends heavily on usage and what is secured." \
  'MD5' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'MD5' \
  "5_cryptocred_ciphers_md5.txt"

  grepit_search "SHA1. Security depends heavily on usage and what is secured." \
  'SHA1' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SHA-?1' \
  "4_cryptocred_ciphers_sha1_uppercase.txt"

  grepit_search "SHA1. Security depends heavily on usage and what is secured." \
  'sha1' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'sha-?1' \
  "4_cryptocred_ciphers_sha1_lowercase.txt"

  grepit_search "SHA256. Security depends heavily on usage and what is secured." \
  'SHA256' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SHA-?256' \
  "4_cryptocred_ciphers_sha256.txt" \
  "-i"

  grepit_search "SHA256. Security depends heavily on usage and what is secured." \
  'SHA512' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'SHA-?512' \
  "4_cryptocred_ciphers_sha512.txt" \
  "-i"

  grepit_search "PBKDF2. Security depends heavily on usage and what is secured." \
  'PBKDF2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'PBKDF2' \
  "4_cryptocred_ciphers_PBKDF2.txt" \
  "-i"

  grepit_search "HMAC. Security depends heavily on usage and what is secured." \
  'HMAC' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'HMAC' \
  "4_cryptocred_ciphers_hmac.txt" \
  "-i"

  grepit_search "NTLM. Security depends heavily on usage and what is secured." \
  'NTLM' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'NTLM' \
  "4_cryptocred_ciphers_ntlm.txt"

  grepit_search "Kerberos. Security depends heavily on usage and what is secured." \
  'Kerberos' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'kerberos' \
  "4_cryptocred_ciphers_kerberos.txt" \
  "-i"

  # take care with the next regex, ! has a special meaning in double quoted strings but not in single quoted
  grepit_search "Hash" \
  'hash_value' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'hash(?!(table|map|set|code))' \
  "6_cryptocred_hash.txt" \
  "-i"

  grepit_search 'Find *nix passwd or shadow files.' \
  '_xcsbuildagent:*:239:239:Xcode Server Build Agent:/var/empty:/usr/bin/false' \
  '/Users/eh2pasz/workspace/ios/CCB/CCB/Classes/CBSaver.h:23:46: note: passing argument to parameter "name" here^M+ (NSString *)loadStringWithName:(NSString *)name; 1b:ee:24:46:0c:17:' \
  "[^:]{3,${WILDCARD_SHORT}}:[^:]{1,${WILDCARD_LONG}}:\d{0,${WILDCARD_SHORT}}:\d{0,${WILDCARD_SHORT}}:[^:]{0,${WILDCARD_LONG}}:[^:]{0,${WILDCARD_LONG}}:[^:]*$" \
  "1_cryptocred_passwd_or_shadow_files.txt" \
  "-i"

  grepit_search "Encryption key and variants of it" \
  'encrypt the key' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "encrypt.{0,${WILDCARD_SHORT}}key" \
  "2_cryptocred_encryption_key.txt" \
  "-i"

  grepit_search "Sources of entropy: /dev/random and /dev/urandom" \
  '/dev/urandom' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "/dev/u?random" \
  "4_cryptocred_dev_random.txt"

  grepit_search "Narrow search for certificate and keys specifics of base64 encoded format" \
  'BEGIN CERTIFICATE' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'BEGIN CERTIFICATE' \
  "2_cryptocred_certificates_and_keys_narrow_begin-certificate.txt"

  grepit_search "Narrow search for certificate and keys specifics of base64 encoded format" \
  'PRIVATE KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'PRIVATE KEY' \
  "1_cryptocred_certificates_and_keys_narrow_private-key.txt"

  grepit_search "Narrow search for certificate and keys specifics of base64 encoded format" \
  'PUBLIC KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'PUBLIC KEY' \
  "2_cryptocred_certificates_and_keys_narrow_public-key.txt"

  grepit_search "Wide search for certificate and keys specifics of base64 encoded format" \
  'begin certificate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "BEGIN.{0,${WILDCARD_SHORT}}CERTIFICATE" \
  "5_cryptocred_certificates_and_keys_wide_begin-certificate.txt" \
  "-i"

  grepit_search "Wide search for certificate and keys specifics of base64 encoded format" \
  'private key' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "PRIVATE.{0,${WILDCARD_SHORT}}KEY" \
  "5_cryptocred_certificates_and_keys_wide_private-key.txt" \
  "-i"

  grepit_search "Wide search for certificate and keys specifics of base64 encoded format" \
  'public key' \
  'public String getBlaKey' \
  "PUBLIC.{0,${WILDCARD_SHORT}}KEY" \
  "5_cryptocred_certificates_and_keys_wide_public-key.txt" \
  "-i"

  grepit_search "Salt for a hashing algorithm?" \
  'Salt or salt' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[Ss]alt" \
  "6_cryptocred_salt1.txt"

  grepit_search "Salt for a hashing algorithm?" \
  'SALT' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SALT" \
  "6_cryptocred_salt2.txt"

  grepit_search "JWT tokens?" \
  'JWT' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "JWT" \
  "6_cryptocred_jwt.txt"

  grepit_search "Hexdigest" \
  'hex-digest' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "hex.?digest" \
  "6_cryptocred_hexdigest.txt" \
  "-i"

  grepit_search "Default password" \
  'default-password' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'default.?password' \
  "2_cryptocred_default_password.txt" \
  "-i"

  grepit_search "Password and variants of it" \
  'pass-word or passwd' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'pass.?wo?r?d' \
  "4_cryptocred_password.txt" \
  "-i"

  grepit_search "Password verification methods, interesting to see if timing " \
  'verifyPassword' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'verify.?pass.?wo?r?d' \
  "3_cryptocred_verify_password.txt" \
  "-i"

  grepit_search "Encoded password and variants of it" \
  'encoded pw = 0x1234' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'encoded.?pw' \
  "4_cryptocred_encoded_pw.txt" \
  "-i"

  grepit_search "PW abbrevation for password" \
  'PW=1234' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'PW.?=' \
  "5_cryptocred_pw_capitalcase.txt"

  grepit_search "PWD abbrevation for password" \
  'PWD' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'PWD' \
  "5_cryptocred_pwd_uppercase.txt"

  grepit_search "pwd abbrevation for password" \
  'pwd' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'pwd' \
  "5_cryptocred_pwd_lowercase.txt"

  grepit_search "Pwd abbrevation for password" \
  'Pwd' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Pwd' \
  "5_cryptocred_pwd_capitalcase.txt"

  grepit_search "The Windows cmd.exe of adding a new user with a password written directly into the cmd.exe. Often found in bad-practice Windows batch scripts or log files." \
  'net user ALongUserNameExampleHere ALongPaSSwOrdExampleHere /add' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "net user.{0,${WILDCARD_LONG}}/add" \
  "1_cryptocred_net_user_add.txt" \
  "-i"

  grepit_search "Adding a new user in batch scripts. Often found in bad-practice Windows batch scripts or log files." \
  'AddUser bla' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AddUser " \
  "2_cryptocred_adduser1.txt"

  grepit_search "Adding a new user in bash scripts. Often found in bad-practice bash scripts or log files." \
  'adduser bla' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "adduser " \
  "2_cryptocred_adduser2.txt"

  grepit_search "Adding a new user in bash scripts. Often found in bad-practice bash scripts or log files." \
  'useradd bla' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "useradd " \
  "2_cryptocred_useradd.txt"

  grepit_search "Insecure registry file specifying that anonymous upload via FTP is possible." \
  '"AllowAnonymous"=dword:00000001 and "AllowAnonymousUpload"=dword:00000001' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AllowAnonymous.{0,${WILDCARD_SHORT}}0001" \
  "2_cryptocred_allowanonymous.txt"

  grepit_search "Disabled Authentication?" \
  '"UseAuthentication"=dword:00000001' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "UseAuthentication" \
  "2_cryptocred_useauthentication.txt"

  grepit_search "Credentials. Included everything 'creden' because some programers write credencials instead of credentials and such things." \
  'credentials=1234' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "creden.{0,${WILDCARD_SHORT}}=.?[\"'\d]" \
  "2_cryptocred_credentials_narrow.txt" \
  "-i"

  grepit_search "Credentials. Included everything 'creden' because some programers write credencials instead of credentials and such things." \
  'credentials' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'creden' \
  "5_cryptocred_credentials_wide.txt" \
  "-i"

  grepit_search "Passcode and variants of it" \
  'passcode = 123' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pass.?code.{0,${WILDCARD_SHORT}}=.?[\"'\d]" \
  "2_cryptocred_passcode_narrow.txt" \
  "-i"

  grepit_search "Passcode and variants of it" \
  'passcode = "123"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pass.?code" \
  "5_cryptocred_passcode_wide.txt" \
  "-i"

  grepit_search "Passphrase and variants of it" \
  'passphrase = "123"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pass.?phrase.{0,${WILDCARD_SHORT}}=.?[\"'\d]" \
  "2_cryptocred_passphrase_narrow.txt" \
  "-i"

  grepit_search "Passphrase and variants of it" \
  'passphrase' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pass.?phrase" \
  "5_cryptocred_passphrase_wide.txt" \
  "-i"

  grepit_search "Secret and variants of it" \
  'secret = "123"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "se?3?cre?3?t.{0,${WILDCARD_SHORT}}=.?[\"'\d]" \
  "2_cryptocred_secret_narrow.txt" \
  "-i"

  grepit_search "Secret and variants of it" \
  'secret' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "se?3?cre?3?t" \
  "5_cryptocred_secret_wide.txt" \
  "-i"

  grepit_search "PIN code and variants of it" \
  'pin code = "123"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pin.?code.{0,${WILDCARD_SHORT}}=.?[\"'\d]" \
  "2_cryptocred_pin_code_narrow.txt" \
  "-i"

  grepit_search "PIN code and variants of it" \
  'pin code' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pin.?code" \
  "5_cryptocred_pin_code_wide.txt" \
  "-i"

  grepit_search "Proxy-Authorization" \
  'ProxyAuthorisation' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Proxy.?Authoris?z?ation' \
  "5_cryptocred_proxy-authorization.txt" \
  "-i"

  grepit_search "Authorization" \
  'Authorisation' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Authori[sz]ation' \
  "5_cryptocred_authorization.txt" \
  "-i"

  grepit_search "Authentication" \
  'Authentication' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Authentication' \
  "5_cryptocred_authentication.txt" \
  "-i"

  grepit_search "SSL usage with requireSSL" \
  'requireSSL' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "require.{0,${WILDCARD_SHORT}}SSL" \
  "4_cryptocred_ssl_usage_require-ssl.txt" \
  "-i"

  grepit_search "SSL usage with useSSL" \
  'use ssl' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "use.{0,${WILDCARD_SHORT}}SSL" \
  "4_cryptocred_ssl_usage_use-ssl.txt" \
  "-i"

  grepit_search "TLS usage with require TLS" \
  'require TLS' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "require.{0,${WILDCARD_SHORT}}TLS" \
  "4_cryptocred_tls_usage_require-tls.txt" \
  "-i"

  grepit_search "TLS usage with use TLS" \
  'use TLS' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "use.{0,${WILDCARD_SHORT}}TLS" \
  "4_cryptocred_tls_usage_use-tls.txt" \
  "-i"

  grepit_search "Ignore SSL errors, such as the --ignore-ssl-errors switch for phantomjs" \
  '--ignore-ssl-errors=true' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "ignore-ssl-errors" \
  "2_cryptocred_ignore_ssl_errors.txt" \
  "-i"

  grepit_search "Accept insecure certificates for webdriver, see https://developer.mozilla.org/en-US/docs/Web/WebDriver/Capabilities/acceptInsecureCerts" \
  'session = webdriver.Firefox(capabilities={"acceptInsecureCerts": True})' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "acceptInsecureCerts" \
  "2_cryptocred_acceptInsecureCerts.txt"

  grepit_search "Accept all certificates for webdriver" \
  'cap["acceptSslCerts"]=False' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "acceptSslCerts" \
  "2_cryptocred_acceptSslCerts.txt" \
  "-i"

  grepit_search "Narrow password search" \
  '--password=' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "--password=" \
  "2_cryptocred_password_equals_switch.txt" \
  "-i"

  grepit_search "Narrow GPG passphrase command line" \
  '-Dgpg.passphrase=foobarbaz' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "-Dgpg.passphrase=" \
  "2_cryptocred_gpg_passphrase.txt" \
  "-i"

  grepit_search "client_secret" \
  '"client_secret":"foo"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "client_secret" \
  "2_cryptocred_client_secret.txt"

  grepit_search "OpenSSL command line encryption parameter ENC for AES etc." \
  'openssl enc -aes-256-cbc -d -in ' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl enc" \
  "2_cryptocred_openssl_enc.txt"

  grepit_search "OpenSSL command line parameter pkcs12 for storing keys" \
  'openssl pkcs12' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl pkcs12" \
  "2_cryptocred_openssl_pkcs12.txt"

  grepit_search "OpenSSL command line parameter RSA for storing keys" \
  'openssl rsa' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl rsa" \
  "2_cryptocred_openssl_rsa.txt"

  grepit_search "OpenSSL command line parameter verify for verifying signatures" \
  'openssl verify' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl verify" \
  "2_cryptocred_openssl_verify.txt"

  grepit_search "OpenSSL command line parameter verify for x509 certificate management" \
  'openssl x509' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl x509" \
  "2_cryptocred_openssl_x509.txt"

  grepit_search "OpenSSL command line parameter digest verifying" \
  'openssl dgst' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl dgst" \
  "2_cryptocred_openssl_dgst.txt"

  grepit_search "OpenSSL command line parameter s_client for doing connections" \
  'openssl s_client' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl s_client" \
  "3_cryptocred_openssl_s_client.txt"

  grepit_search "OpenSSL command line parameter s_server for receiving connections" \
  'openssl s_server' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "openssl s_server" \
  "3_cryptocred_openssl_s_server.txt"
}

grepit_module_api_keys() {
  print_output "[*] Starting Grepit API keys module" "no_log"

  grepit_search "Generic access token search" \
  '?access_token=' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "access_token" \
  "2_apikeys_access_token.txt"

  grepit_search "AccessKeyId AWS secret" \
  '?AccessKeyId=' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AccessKeyId" \
  "3_apikeys_AccessKeyId.txt"

  grepit_search "AZURE_CLIENT_SECRET Azure environment variable" \
  'AZURE_CLIENT_SECRET' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AZURE_CLIENT_SECRET" \
  "2_apikeys_AZURE_CLIENT_SECRET.txt"

  grepit_search "AZURE_CLIENT_ID Azure environment variable" \
  'AZURE_CLIENT_ID' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AZURE_CLIENT_ID" \
  "3_apikeys_AZURE_CLIENT_ID.txt"

  grepit_search "AMAZON_AWS_SECRET_ACCESS_KEY AWS environment variable" \
  'AMAZON_AWS_SECRET_ACCESS_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AMAZON_AWS_SECRET_ACCESS_KEY" \
  "2_apikeys_AMAZON_AWS_SECRET_ACCESS_KEY.txt"

  grepit_search "AWS_SECRET_ACCESS_KEY AWS environment variable" \
  'AWS_SECRET_ACCESS_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AWS_SECRET_ACCESS_KEY" \
  "2_apikeys_AWS_SECRET_ACCESS_KEY.txt"

  grepit_search "AMAZON_AWS_ACCESS_KEY_ID AWS environment variable" \
  'AMAZON_AWS_ACCESS_KEY_ID' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AMAZON_AWS_ACCESS_KEY_ID" \
  "3_apikeys_AMAZON_AWS_ACCESS_KEY_ID.txt"

  grepit_search "AWS_ACCESS_KEY_ID AWS environment variable" \
  'AWS_ACCESS_KEY_ID' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AWS_ACCESS_KEY_ID" \
  "3_apikeys_AWS_ACCESS_KEY_ID.txt"

  grepit_search "AZURE_USERNAME environment variable" \
  'AZURE_USERNAME' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AZURE_USERNAME" \
  "3_apikeys_AZURE_USERNAME.txt"

  grepit_search "AZURE_PASSWORD environment variable" \
  'AZURE_PASSWORD' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "AZURE_PASSWORD" \
  "2_apikeys_AZURE_PASSWORD.txt"

  grepit_search "MSI_ENDPOINT environment variable" \
  'MSI_ENDPOINT' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "MSI_ENDPOINT" \
  "3_apikeys_MSI_ENDPOINT.txt"

  grepit_search "MSI_SECRET environment variable" \
  'MSI_SECRET' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "MSI_SECRET" \
  "2_apikeys_MSI_SECRET.txt"

  grepit_search "binance_api environment variable" \
  'binance_api' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "binance_api" \
  "3_apikeys_binance_api.txt"

  grepit_search "binance_secret environment variable" \
  'binance_secret' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "binance_secret" \
  "3_apikeys_binance_secret.txt"

  grepit_search "BITTREX_API_KEY environment variable" \
  'BITTREX_API_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "BITTREX_API_KEY" \
  "3_apikeys_BITTREX_API_KEY.txt"

  grepit_search "BITTREX_API_SECRET environment variable" \
  'BITTREX_API_SECRET' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "BITTREX_API_SECRET" \
  "3_apikeys_BITTREX_API_SECRET.txt"

  grepit_search "CIRCLE_TOKEN environment variable" \
  'CIRCLE_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CIRCLE_TOKEN" \
  "3_apikeys_CIRCLE_TOKEN.txt"

  grepit_search "DIGITALOCEAN_ACCESS_TOKEN environment variable" \
  'DIGITALOCEAN_ACCESS_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "DIGITALOCEAN_ACCESS_TOKEN" \
  "3_apikeys_DIGITALOCEAN_ACCESS_TOKEN.txt"

  grepit_search "DOCKERHUB_PASSWORD environment variable" \
  'DOCKERHUB_PASSWORD' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "DOCKERHUB_PASSWORD" \
  "2_apikeys_DOCKERHUB_PASSWORD.txt"

  grepit_search "ITC_PASSWORD environment variable" \
  'ITC_PASSWORD' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "ITC_PASSWORD" \
  "2_apikeys_ITC_PASSWORD.txt"

  grepit_search "FACEBOOK_APP_ID environment variable" \
  'FACEBOOK_APP_ID' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "FACEBOOK_APP_ID" \
  "3_apikeys_FACEBOOK_APP_ID.txt"

  grepit_search "FACEBOOK_APP_SECRET environment variable" \
  'FACEBOOK_APP_SECRET' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "FACEBOOK_APP_SECRET" \
  "3_apikeys_FACEBOOK_APP_SECRET.txt"

  grepit_search "FACEBOOK_ACCESS_TOKEN environment variable" \
  'FACEBOOK_ACCESS_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "FACEBOOK_ACCESS_TOKEN" \
  "3_apikeys_FACEBOOK_ACCESS_TOKEN.txt"

  grepit_search "GH_TOKEN environment variable" \
  'GH_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GH_TOKEN" \
  "3_apikeys_GH_TOKEN.txt"

  grepit_search "GITHUB_TOKEN environment variable" \
  'GITHUB_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GITHUB_TOKEN" \
  "3_apikeys_GITHUB_TOKEN.txt"

  grepit_search "GH_ENTERPRISE_TOKEN environment variable" \
  'GH_ENTERPRISE_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GH_ENTERPRISE_TOKEN" \
  "3_apikeys_GH_ENTERPRISE_TOKEN.txt"

  grepit_search "GITHUB_ENTERPRISE_TOKEN environment variable" \
  'GITHUB_ENTERPRISE_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GITHUB_ENTERPRISE_TOKEN" \
  "3_apikeys_GITHUB_ENTERPRISE_TOKEN.txt"

  grepit_search "GOOGLE_APPLICATION_CREDENTIALS environment variable" \
  'GOOGLE_APPLICATION_CREDENTIALS' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GOOGLE_APPLICATION_CREDENTIALS" \
  "3_apikeys_GOOGLE_APPLICATION_CREDENTIALS.txt"

  grepit_search "GOOGLE_API_KEY environment variable" \
  'GOOGLE_API_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GOOGLE_API_KEY" \
  "3_apikeys_GOOGLE_API_KEY.txt"

  grepit_search "CI_DEPLOY_USER environment variable" \
  'CI_DEPLOY_USER' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CI_DEPLOY_USER" \
  "3_apikeys_CI_DEPLOY_USER.txt"

  grepit_search "CI_DEPLOY_PASSWORD environment variable" \
  'CI_DEPLOY_PASSWORD' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CI_DEPLOY_PASSWORD" \
  "2_apikeys_CI_DEPLOY_PASSWORD.txt"

  grepit_search "GITLAB_USER_LOGIN environment variable" \
  'GITLAB_USER_LOGIN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GITLAB_USER_LOGIN" \
  "3_apikeys_GITLAB_USER_LOGIN.txt"

  grepit_search "CI_JOB_JWT environment variable" \
  'CI_JOB_JWT' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CI_JOB_JWT" \
  "3_apikeys_CI_JOB_JWT.txt"

  grepit_search "CI_JOB_JWT_V2 environment variable" \
  'CI_JOB_JWT_V2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CI_JOB_JWT_V2" \
  "3_apikeys_CI_JOB_JWT_V2.txt"

  grepit_search "CI_JOB_TOKEN environment variable" \
  'CI_JOB_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CI_JOB_TOKEN" \
  "3_apikeys_CI_JOB_TOKEN.txt"

  grepit_search "MAILGUN_API_KEY environment variable" \
  'MAILGUN_API_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "MAILGUN_API_KEY" \
  "3_apikeys_MAILGUN_API_KEY.txt"

  grepit_search "MCLI_PRIVATE_API_KEY environment variable" \
  'MCLI_PRIVATE_API_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "MCLI_PRIVATE_API_KEY" \
  "3_apikeys_MCLI_PRIVATE_API_KEY.txt"

  grepit_search "MCLI_PUBLIC_API_KEY environment variable" \
  'MCLI_PUBLIC_API_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "MCLI_PUBLIC_API_KEY" \
  "3_apikeys_MCLI_PUBLIC_API_KEY.txt"

  grepit_search "NPM_TOKEN environment variable" \
  'NPM_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "NPM_TOKEN" \
  "3_apikeys_NPM_TOKEN.txt"

  grepit_search "OS_PASSWORD environment variable" \
  'OS_PASSWORD' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "OS_PASSWORD" \
  "2_apikeys_OS_PASSWORD.txt"

  grepit_search "PERCY_TOKEN environment variable" \
  'PERCY_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "PERCY_TOKEN" \
  "3_apikeys_PERCY_TOKEN.txt"

  grepit_search "SENTRY_AUTH_TOKEN environment variable" \
  'SENTRY_AUTH_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SENTRY_AUTH_TOKEN" \
  "3_apikeys_SENTRY_AUTH_TOKEN.txt"

  grepit_search "SLACK_TOKEN environment variable" \
  'SLACK_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SLACK_TOKEN" \
  "3_apikeys_SLACK_TOKEN.txt"

  grepit_search "square_access_token environment variable" \
  'square_access_token' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "square_access_token" \
  "3_apikeys_square_access_token.txt"

  grepit_search "square_oauth_secret environment variable" \
  'square_oauth_secret' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "square_oauth_secret" \
  "2_apikeys_square_oauth_secret.txt"

  grepit_search "STRIPE_API_KEY environment variable" \
  'STRIPE_API_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "STRIPE_API_KEY" \
  "3_apikeys_STRIPE_API_KEY.txt"

  grepit_search "STRIPE_DEVICE_NAME environment variable" \
  'STRIPE_DEVICE_NAME' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "STRIPE_DEVICE_NAME" \
  "3_apikeys_STRIPE_DEVICE_NAME.txt"

  grepit_search "TWILIO_ACCOUNT_SID environment variable" \
  'TWILIO_ACCOUNT_SID' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TWILIO_ACCOUNT_SID" \
  "3_apikeys_TWILIO_ACCOUNT_SID.txt"

  grepit_search "TWILIO_AUTH_TOKEN environment variable" \
  'TWILIO_AUTH_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TWILIO_AUTH_TOKEN" \
  "2_apikeys_TWILIO_AUTH_TOKEN.txt"

  grepit_search "CONSUMER_KEY environment variable" \
  'CONSUMER_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CONSUMER_KEY" \
  "3_apikeys_CONSUMER_KEY.txt"

  grepit_search "CONSUMER_SECRET environment variable" \
  'CONSUMER_SECRET' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CONSUMER_SECRET" \
  "2_apikeys_CONSUMER_SECRET.txt"

  grepit_search "TRAVIS_SUDO environment variable" \
  'TRAVIS_SUDO' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TRAVIS_SUDO" \
  "3_apikeys_TRAVIS_SUDO.txt"

  grepit_search "TRAVIS_OS_NAME environment variable" \
  'TRAVIS_OS_NAME' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TRAVIS_OS_NAME" \
  "3_apikeys_TRAVIS_OS_NAME.txt"

  grepit_search "TRAVIS_SECURE_ENV_VARS environment variable" \
  'TRAVIS_SECURE_ENV_VARS' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TRAVIS_SECURE_ENV_VARS" \
  "3_apikeys_TRAVIS_SECURE_ENV_VARS.txt"

  grepit_search "VAULT_TOKEN environment variable" \
  'VAULT_TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "VAULT_TOKEN" \
  "3_apikeys_VAULT_TOKEN.txt"

  grepit_search "VAULT_CLIENT_KEY environment variable" \
  'VAULT_CLIENT_KEY' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "VAULT_CLIENT_KEY" \
  "2_apikeys_VAULT_CLIENT_KEY.txt"

  grepit_search "TOKEN environment variable" \
  'TOKEN' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "TOKEN" \
  "4_apikeys_TOKEN.txt"

  grepit_search "VULTR_ACCESS environment variable" \
  'VULTR_ACCESS' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "VULTR_ACCESS" \
  "3_apikeys_VULTR_ACCESS.txt"

  grepit_search "VULTR_SECRET environment variable" \
  'VULTR_SECRET' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "VULTR_SECRET" \
  "2_apikeys_VULTR_SECRET.txt"

  grepit_search "Google OAUTH2 service account" \
  '"type": "service_account"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "service_account" \
  "4_apikeys_service_account.txt"

  grepit_search "Github token" \
  '0GITHUB_TOKEN=' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GITHUB_TOKEN" \
  "2_apikeys_githubToken.txt"

  grepit_search "Pushover token as explained in https://github.com/marketplace/actions/pushover-actions" \
  'PUSHOVER_TOKEN: ${{ secrets.PUSHOVER_TOKEN }}' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "PUSHOVER_TOKEN" \
  "2_apikeys_pushoverToken.txt"

  grepit_search "Kubernetes Kubeconfig token usually located in ${HOME}/.kube/config" \
  'kubeconfig-u-cebyer2bzx.q-71niw:h4jzfpqcyuzf3nu84b02aqhjizy65v2vjivbqbvj4bwnutewv0aq1n' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "kubeconfig-[^\:]{0,${WILDCARD_LONG}}:." \
  "2_apikeys_kubeconfig.txt"
}

grepit_module_asm_native() {
  print_output "[*] Starting Grepit Assembly native module" "no_log"
  # Whatever you can usually find in a disassembly
  # This is a very experimental section...

  grepit_search "Checking if sleep is hooked via Windows API by checking CPU clock delta to detect sandboxes (sandboxes such as Windows Defender hook sleep calls) via GetTickCount" \
  'call cs:GetTickCount' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "GetTickCount" \
  "4_assembly_GetTickCount.txt"
}

grepit_module_general() {
  print_output "[*] Starting Grepit General module" "no_log"

  grepit_search "A generic templating pattern that is used in HTML generation of Java (JSP), Ruby and client-side JavaScript libraries." \
  'In Java <%=bean.getName()%> or in ruby <%= parameter[:value] %>' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '<%=' \
  "2_general_html_templating.txt"

  grepit_search "Superuser. Sometimes the root user of *nix is referenced, sometimes it is about root detection on mobile phones (e.g. Android Superuser.apk app detection)" \
  'super_user' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "super.?user" \
  "2_general_superuser.txt" \
  "-i"

  grepit_search "Root user in Docker files" \
  'USER root' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "USER root" \
  "3_general_docker_root_user.txt"

  grepit_search "Su binary" \
  'sudo binary' \
  'suite.api.java.rql.construct.Binary, super(name, contentType, binary' \
  "su.{0,3}binary" \
  "5_general_su-binary.txt" \
  "-i"

  grepit_search "no_root_squash allows NFS clients to connect as root and for example plant suid binaries on the server, that if executed by any user exploit the server as root" \
  'no_root_squash' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "no_root_squash" \
  "2_general_no_root_squash.txt"

  grepit_search "sec=sys means NFS clients connect to NFS with the old UID/GID system, without encryption or integrity checks (instead of Kerberos)" \
  'sec=sys' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sec=sys" \
  "2_general_sec_equals_sys.txt"

  grepit_search "sudo" \
  'sudo make me a sandwich' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sudo\s" \
  "3_general_sudo.txt"

  grepit_search "Impersonate is often used in functionality which can be used to act as another user" \
  'impersonate' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "impersonate" \
  "4_general_impersonate.txt" \
  "-i"

  grepit_search "Denying is often used for filtering, etc." \
  'deny' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[Dd]eny" \
  "5_general_deny.txt"

  grepit_search "Exec mostly means executing on OS." \
  'runTime.exec("echo "+unsanitized_input);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "exec\s{0,${WILDCARD_SHORT}}\(" \
  "4_general_exec_narrow.txt"

  grepit_search "Exec mostly means executing on OS." \
  'runTime.exec("echo "+unsanitized_input);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "exec" \
  "5_general_exec_wide.txt"

  grepit_search "Eval mostly means evaluating commands." \
  'eval (' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "eval\s{0,${WILDCARD_SHORT}}\(" \
  "4_general_eval_narrow.txt"

  grepit_search "Eval mostly means evaluating commands." \
  'eval' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "eval" \
  "5_general_eval_wide.txt"

  grepit_search "Syscall: Command execution?" \
  'syscall(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sys.?call\s{0,${WILDCARD_SHORT}}\(" \
  "4_general_syscall_narrow.txt" \
  "-i"

  grepit_search "Syscall: Command execution?" \
  'syscall' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sys.?call" \
  "5_general_syscall_wide.txt" \
  "-i"

  grepit_search "system: Command execution?" \
  'system(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "system\s{0,${WILDCARD_SHORT}}\(" \
  "4_general_system_narrow.txt" \
  "-i"

  grepit_search "system: Command execution?" \
  'system' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "system" \
  "5_general_system_wide.txt" \
  "-i"

  grepit_search "Search for binary paths or similar: Command execution?" \
  'place = "/usr/bin/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/usr/" \
  "4_general_usr_dir.txt"

  grepit_search "Search for binary paths or similar: Command execution?" \
  'place = "/opt/bin/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/opt/" \
  "4_general_opt_dir.txt"

  grepit_search "Search for binary paths or similar: Command execution?" \
  'place = "/bin/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/bin/" \
  "5_general_bin_dir.txt"

  grepit_search "Search for binary paths or similar: Command execution?" \
  'place = "/sbin/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/sbin/" \
  "4_general_sbin_dir.txt"

  grepit_search "Search for binary paths or similar: Command execution?" \
  'place = "/dev/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/dev/" \
  "4_general_dev_dir.txt"

  grepit_search "Search for binary paths or similar: Command execution?" \
  'place = "/tmp/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/tmp/" \
  "3_general_tmp_dir.txt"

  grepit_search "Configuration files in /etc/" \
  'place = "/etc/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/etc/" \
  "3_general_etc_dir.txt"

  grepit_search "Configuration files in /mnt/" \
  'place = "/mnt/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/mnt/" \
  "3_general_mnt_dir.txt"

  grepit_search "Reading values from /proc/" \
  'place = "/proc/softwareupdate"' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[\"']/proc/" \
  "3_general_proc_dir.txt"

  grepit_search "pipeline: Command execution?" \
  'pipeline(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pipeline\s{0,${WILDCARD_SHORT}}\(" \
  "4_general_pipeline_narrow.txt" \
  "-i"

  grepit_search "pipeline: Command execution?" \
  'pipeline' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "pipeline" \
  "5_general_pipeline_wide.txt" \
  "-i"

  grepit_search "popen: Command execution?" \
  'popen(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "popen\s{0,${WILDCARD_SHORT}}\(" \
  "4_general_popen_narrow.txt" \
  "-i"

  grepit_search "popen: Command execution?" \
  'popen' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "popen" \
  "5_general_popen_wide.txt" \
  "-i"

  grepit_search "spawn: Command execution?" \
  'spawn(' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "spawn\s{0,${WILDCARD_SHORT}}\(" \
  "4_general_spawn_narrow.txt" \
  "-i"

  grepit_search "spawn: Command execution?" \
  'spawn' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "spawn" \
  "5_general_spawn_wide.txt" \
  "-i"

  grepit_search "chgrp: Change group command" \
  'chgrp' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "chgrp" \
  "5_general_chgrp.txt" \
  "-i"

  grepit_search "chown: Change owner command" \
  'chown' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "chown" \
  "5_general_chown.txt" \
  "-i"

  grepit_search "chmod: Change mode (permissions) command" \
  'chmod' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "chmod" \
  "5_general_chmod.txt" \
  "-i"

  grepit_search "Session timeouts should be reasonable short for things like sessions for web logins but can also lead to denial of service conditions in other cases." \
  'session-timeout' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'session-?\s?time-?\s?out' \
  "4_general_session_timeout.txt" \
  "-i"

  grepit_search "Timeout. Whatever timeout this might be, that might be interesting." \
  'timeout' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'time-?\s?out' \
  "5_general_session_timeout.txt" \
  "-i"

  grepit_search "General setcookie command used in HTTP, important to see HTTPonly/secure flags, path setting, etc." \
  'setcookie' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'setcookie' \
  "4_general_setcookie.txt" \
  "-i"

  grepit_search "General serialisation code, can lead to command execution" \
  'serialise' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'seriali[sz]e' \
  "4_general_serialise.txt" \
  "-i"

  grepit_search "Relative paths. May allow an attacker to put something early in the search path (if parts are user supplied input) and overwrite behavior" \
  '../../' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\./' \
  "5_general_relative_paths.txt" \
  "-i"

  grepit_search "Search for the word credit card" \
  'credit-card' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'credit.?card' \
  "4_general_creditcard.txt" \
  "-i"

  grepit_search "Update code and general update strategy weaknesses" \
  'Update' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'update' \
  "6_general_update.txt" \
  "-i"

  grepit_search "Backup code and general backup strategy weaknesses" \
  'Backup' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'backup' \
  "6_general_backup.txt" \
  "-i"

  grepit_search "Debugger related content. In JavaScript, the debugger statement (debugger;) is basically a breakpoint, see https://sonarqube.com/coding_rules#types=VULNERABILITY|languages=js" \
  'debugger' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "debugger" \
  "5_general_debugger.txt" \
  "-i"

  grepit_search "Kernel. A reference to something low level in a Kernel?" \
  'Kernel' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Kernel' \
  "5_general_kernel.txt" \
  "-i"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "Email addresses" \
  'example-email_address-@example-domain.com' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}\b' \
  "6_general_email.txt" \
  "-i"

  grepit_search "TODOs, unfinished and insecure things?" \
  'Todo:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '[Tt]odo' \
  "5_general_todo_capital_and_lower.txt"

  grepit_search "TODOs, unfinished and insecure things?" \
  'TODO:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'TODO' \
  "5_general_todo_uppercase.txt"

  grepit_search "Workarounds, maybe they work around security?" \
  'workaround: ' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'workaround' \
  "6_general_workaround.txt" \
  "-i"

  grepit_search "Hack. Developers sometimes hack something around security." \
  'hack' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'hack' \
  "5_general_hack.txt" \
  "-i"

  grepit_search "Crack. Sounds suspicious." \
  'crack' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'crack' \
  "5_general_crack.txt" \
  "-i"

  grepit_search "Trick. Sounds suspicious." \
  'trick' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'trick' \
  "5_general_trick.txt" \
  "-i"

  grepit_search "Exploit and variants of it. Sounds suspicious." \
  'exploit' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'xploit' \
  "5_general_exploit.txt" \
  "-i"

  grepit_search "Bypass. Sounds suspicious, what do they bypass exactly?" \
  'bypass' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'bypass' \
  "5_general_bypass.txt" \
  "-i"

  grepit_search "Backdoor. Sounds suspicious, why would anyone ever use this word?" \
  'back-door' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "back.{0,${WILDCARD_SHORT}}door" \
  "3_general_backdoor.txt" \
  "-i"

  grepit_search "Backd00r. Sounds suspicious, why would anyone ever use this word?" \
  'back-d00r' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "back.{0,${WILDCARD_SHORT}}d00r" \
  "5_general_backd00r.txt" \
  "-i"

  grepit_search "Fake. Sounds suspicious." \
  'fake:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'fake' \
  "5_general_fake.txt" \
  "-i"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "URIs with authentication information specified as ://username:password@example.org" \
  'http://username:password@example.com' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "://[^ :/]{1,${WILDCARD_SHORT}}:[^ :/]{1,${WILDCARD_SHORT}}@" \
  "1_general_uris_auth_info_narrow.txt" \
  "-i"

  # Take care with the following regex, @ has a special meaning in double quoted strings, but not in single quoted strings
  grepit_search "URIs with authentication information specified as username:password@example.org" \
  'username:password@example.com' \
  'android:duration="@integer/animator_heartbeat_scaling_duration" or addObject:NSLocalizedString(@' \
  "[^ \:/]{1,${WILDCARD_SHORT}}:[^ \:/]{1,${WILDCARD_SHORT}}@" \
  "2_general_uris_auth_info_wide.txt" \
  "-i"

  grepit_search "All HTTPS URIs" \
  'https://example.com' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'https://' \
  "5_general_https_urls.txt" \
  "-i"

  grepit_search "All HTTP URIs" \
  'http://example.com' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'http://' \
  "5_general_http_urls.txt" \
  "-i"

  grepit_search "Non-SSL URIs ftp" \
  'ftp://example.com' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'ftp://' \
  "4_general_non_ssl_uris_ftp.txt" \
  "-i"

  grepit_search "Non-SSL URIs socket" \
  'socket://192.168.0.1:3000' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'socket://' \
  "4_general_non_ssl_uris_socket.txt" \
  "-i"

  grepit_search "Non-SSL URIs imap" \
  'imap://example.com' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'imap://' \
  "4_general_non_ssl_uris_imap.txt" \
  "-i"

  grepit_search "file URIs" \
  'file://c/example.txt' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'file://' \
  "4_general_non_ssl_uris_file.txt" \
  "-i"

  grepit_search "jdbc URIs" \
  'jdbc:mysql://localhost/test?password=ABC' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'jdbc:' \
  "3_general_jdbc_uri.txt" \
  "-i"

  grepit_search "Generic database connection string for SQL server. See https://www.connectionstrings.com/sql-server/ for different connection strings." \
  'Server=myServerAddress;Database=myDataBase;Trusted_Connection=True;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "Server=.{0,${WILDCARD_SHORT}};Database=" \
  "2_general_con_str_sqlserver.txt" \
  "-i"

  grepit_search "Generic database connection string for SQL server meaning AD auth is used. See https://www.connectionstrings.com/sql-server/ for different connection strings." \
  'Server=myServerAddress;Database=myDataBase;Trusted_Connection=True;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ";Trusted_Connection=" \
  "4_general_con_str_trusted_sqlserver.txt" \
  "-i"

  grepit_search "Generic database connection string for various databases. See https://www.connectionstrings.com/sql-server/ for different connection strings." \
  'Data Source=myServerAddress;Initial Catalog=myDataBase;Integrated Security=SSPI;User ID=myDomain\myUsername;Password=myPassword;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ";Password=" \
  "1_general_con_str_sql_password.txt" \
  "-i"

  grepit_search "Generic database connection string for various databases. See https://www.connectionstrings.com/sql-server/ for different connection strings." \
  'Driver={Oracle in OraHome92};Dbq=myTNSServiceName;Uid=myUsername;Pwd=myPassword;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ";Pwd=" \
  "1_general_con_str_sql_pwd.txt" \
  "-i"

  grepit_search "Generic database connection string for localdb and other dbs. See https://www.connectionstrings.com/sql-server/ for different connection strings." \
  'Server=(localdb)\v11.0;Integrated Security=true;AttachDbFileName=C:\MyFolder\MyData.mdf;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  ";Integrated.Security=" \
  "2_general_con_str_localdb.txt" \
  "-i"

  grepit_search "Hidden things, for example hidden HTML fields" \
  'hidden:' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'hidden' \
  "5_general_hidden.txt" \
  "-i"

  grepit_search "Scheme. Is the first part of a URI aka 'the protocol'." \
  'RouteUrlWithScheme' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'scheme' \
  "7_general_scheme.txt" \
  "-i"

  grepit_search "Schema. Eg. a database schema." \
  'database schema' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'schema' \
  "7_general_schema.txt" \
  "-i"

  grepit_search "WSDL defines web services" \
  'example.wsdl' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'wsdl' \
  "5_general_wsdl.txt" \
  "-i"

  grepit_search "WebView, often used to display HTML content inside native apps" \
  'webview' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'webview' \
  "6_general_webview.txt" \
  "-i"

  grepit_search "Directory listing, usually a bad idea in web servers." \
  'directory-listing' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "directory.listing" \
  "4_general_directory_listing.txt" \
  "-i"

  grepit_search "SQL injection and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'sql-injection' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sql.{0,${WILDCARD_SHORT}}injection" \
  "2_general_sql_injection.txt" \
  "-i"

  grepit_search "XSS. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'XSS' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'XSS' \
  "4_general_xss_uppercase.txt"

  grepit_search "XSS. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'Xss' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'Xss' \
  "4_general_xss_regularcase.txt"

  grepit_search "XSS. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'xss' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'xss' \
  "4_general_xss_lowercase.txt"

  grepit_search "Clickjacking and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'click-jacking' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "click.{0,${WILDCARD_SHORT}}jacking" \
  "2_general_hacking_techniques_clickjacking.txt" \
  "-i"

  grepit_search "XSRF/CSRF and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'xsrf' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[xX]srf" \
  "4_general_hacking_techniques_xsrf_regularcase.txt"

  grepit_search "XSRF/CSRF and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'XSRF' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "XSRF" \
  "3_general_hacking_techniques_xsrf_uppercase.txt"

  grepit_search "XSRF/CSRF and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'csrf' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "[cC]srf" \
  "4_general_hacking_techniques_csrf_regularcase.txt"

  grepit_search "XSRF/CSRF and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'CSRF' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CSRF" \
  "3_general_hacking_techniques_csrf_uppercase.txt"

  grepit_search "Buffer overflow and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'buffer-overflow' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "buffer.{0,${WILDCARD_SHORT}}overflow" \
  "2_general_hacking_techniques_buffer-overflow.txt" \
  "-i"

  grepit_search "Integer overflow and variants of it. Sometimes refered in comments or variable names for code that should prevent it. If you find something interesting that is used for prevention in a framework, you might want to add another grep for that in this script." \
  'integer-overflow' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "integer.{0,${WILDCARD_SHORT}}overflow" \
  "2_general_hacking_techniques_integer-overflow.txt" \
  "-i"

  grepit_search "Obfuscation and variants of it. Might be interesting code where the obfuscation is done. If you find something interesting that is used for obfuscation in a framework, you might want to add another grep for that in this script." \
  'obfuscation' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "obfuscat" \
  "2_general_obfuscation.txt" \
  "-i"

  # take care with the following regex, backticks have to be escaped
  # grepit_search "Everything between backticks, because in Perl and Shell scirpting (eg. cgi-scripts) these are system execs." \
  # '`basename file-var`' \
  # 'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  # "\`.{2,${WILDCARD_LONG}}\`" \
  # "5_general_backticks.txt"\
  # "-i"

  grepit_search "Piping into the mail command is very dangerous, as it interpretes ~! as a command that should be executed, see https://research.securitum.com/fail2ban-remote-code-execution/" \
  'echo "test $userinput" | mail -s "subject" user@example.org' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\|\s{0,${WILDCARD_SHORT}}mail" \
  "2_general_mail_pipe.txt" \
  "-i"

  grepit_search "SQL SELECT statement" \
  'SELECT EXAMPLE, ABC, DEF FROM TABLE' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "SELECT\s.{0,${WILDCARD_LONG}}FROM" \
  "4_general_sql_select.txt" \
  "-i"

  grepit_search "SQL INSERT statement" \
  'INSERT INTO TABLE example VALUES(123);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "INSERT.{0,${WILDCARD_SHORT}}INTO" \
  "4_general_sql_insert.txt" \
  "-i"

  grepit_search "SQL DELETE statement" \
  'DELETE COLUMN WHERE 1=1' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "DELETE.{0,${WILDCARD_LONG}}WHERE" \
  "4_general_sql_delete.txt" \
  "-i"

  grepit_search "SQL CREATE LOGIN statement" \
  'CREATE LOGIN loginName' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "CREATE LOGIN" \
  "2_general_sql_create_login.txt" \
  "-i"

  grepit_search "SQL PWDCOMPARE statement" \
  'SELECT PWDCOMPARE("pass", CAST(LOGINPROPERTY("username", "passwordshash")))....' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "PWDCOMPARE\(" \
  "2_general_sql_pwdcompare.txt" \
  "-i"

  grepit_search "SQL LOGINPROPERTY statement" \
  'SELECT LOGINPROPERTY("username", "passwordshash");' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "LOGINPROPERTY\(" \
  "2_general_sql_loginproperty.txt" \
  "-i"

  grepit_search "MSSQL sp_addlogin statement" \
  'EXEC sp_addlogin @loginame = "username", @passwd = 0x00000000000000000000000000000,@defdb = "DBNAME",@encryptopt = "skip_encryption";' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sp_addlogin" \
  "2_general_sql_sp_addlogin.txt" \
  "-i"

  grepit_search "MSSQL WITH PASSWORD statement" \
  'CREATE LOGIN [USERNAME] WITH PASSWORD = 0x000000000000000000000 HASHED, SID =' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "WITH PASSWORD =" \
  "2_general_sql_with_password.txt" \
  "-i"

  grepit_search "MSSQL rmtpassword attribute" \
  'EXEC master.dbo.sp_addlinkedsrvlogin @rmtsrvname = N"Instance",@useself = N"False",@locallogin = NULL,@rmtuser = N"USERNAME",@rmtpassword = "pass";' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "@rmtpassword" \
  "2_general_sql_rmtpassword.txt" \
  "-i"

  grepit_search "SQL SQLITE" \
  'sqlite' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sqlite" \
  "5_general_sql_sqlite.txt" \
  "-i"

  grepit_search "SQL cursor?" \
  'cursor' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "cursor" \
  "5_general_sql_cursor.txt" \
  "-i"

  grepit_search "sqlcipher, used to encrypt database entries transparently" \
  'sqlcipher' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sqlcipher" \
  "4_general_sql_sqlcipher.txt" \
  "-i"

  # TODO: These regexes can take waaaay too long sometimes, improve performance
  # As the following regex had way too many false positives (thousands of english words match), we require the base64 to include
  # at least one equal sign at the end. The old regex was:
  # '(?:[A-Za-z0-9_-]{4})+(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)'
  grepit_search "Base64 encoded data (that is more than 6 bytes long). This regex won't detect a base64 encoded value over several lines and won't detect one that does not end with an equal sign..." \
  'YWJj YScqKyo6LV/Dpw==' \
  '/target/ //JQLite - the following ones shouldnt be an issue anymore as we require more than 6 bytes: done echo else gen/ ////' \
  '(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)' \
  "5_general_base64_content.txt"
  # case sensitive, the regex is insensitive anyway

  # As the following regex had way too many false positives (thousands of english words match), we require the base64 to include
  # at least one equal sign at the end. The old regex was:
  # '(?:[A-Za-z0-9_-]{4})+(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=|[A-Za-z0-9_-]{4})'
  grepit_search "Base64 URL-safe encoded data (that is more than 6 bytes long). To get from URL-safe base64 to regular base64 you need .replace('-','+').replace('_','/'). This regex won't detect a base64 encoded value over several lines and won't detect one that does not end with an equal sign..." \
  'YScqKyo6LV_Dpw==' \
  '/target/ //JQLite - the following ones shouldnt be an issue anymore as we require more than 6 bytes: done echo else gen/ ////' \
  '(?:[A-Za-z0-9_-]{4}){2,}(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)' \
  "5_general_base64_urlsafe.txt"
  # case sensitive, the regex is insensitive anyway

  grepit_search "Base64 as a word used" \
  'Base64' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'base64' \
  "5_general_base64_word.txt" \
  "-i"

  grepit_search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
  'GNU GPL' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'GNU\sGPL' \
  "6_general_gpl1.txt" \
  "-i"

  grepit_search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
  'GPLv2' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'GPLv2' \
  "6_general_gpl2.txt" \
  "-i"

  grepit_search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
  'GPLv3' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'GPLv3' \
  "6_general_gpl3.txt" \
  "-i"

  grepit_search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
  'GPL Version' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'GPL\sVersion' \
  "6_general_gpl4.txt" \
  "-i"

  grepit_search "GPL violation? Not security related, but your customer might be happy to know such stuff" \
  'General Public License' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'General\sPublic\sLicense' \
  "6_general_gpl5.txt" \
  "-i"

  grepit_search "Stupid: Swear words are often used when things don't work as intended by the developer." \
  'Stupid!' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'stupid' \
  "4_general_swear_stupid.txt" \
  "-i"

  grepit_search "Fuck: Swear words are often used when things don't work as intended by the developer. X-)" \
  'Fuck!' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'fuck' \
  "4_general_swear_fuck.txt" \
  "-i"

  grepit_search "Shit and bullshit: Swear words are often used when things don't work as intended by the developer." \
  'Shit!' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'shit' \
  "4_general_swear_shit.txt" \
  "-i"

  grepit_search "Crap: Swear words are often used when things don't work as intended by the developer." \
  'Crap!' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'crap' \
  "4_general_swear_crap.txt" \
  "-i"

  # IP-Adresses
  # \b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
  #  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
  #  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
  #  (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b
  grepit_search "IP addresses" \
  '192.168.0.1 10.0.0.1' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' \
  "8_general_ip-addresses.txt" \
  "-i"

  grepit_search "Referer is only used for the HTTP Referer usually, it can be specified by the attacker" \
  'referer' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  'referer' \
  "6_general_referer.txt" \
  "-i"

  grepit_search "Generic search for SQL injection, FROM and WHERE being SQL keywords and + meaning string concatenation" \
  'q = "SELECT * from USERS where NAME=" + user;' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "from\s.{0,${WILDCARD_LONG}}\swhere\s.{0,${WILDCARD_LONG}}" \
  "4_general_sqli_generic.txt" \
  "-i"

  grepit_search "A form of query often used for LDAP, should be checked if it doesn't lead to LDAP injection and/or DoS" \
  'String ldap_query = "(&(param=user)(name=" + name_unsanitized + "))";' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "\(&\(.{0,${WILDCARD_SHORT}}=" \
  "5_general_ldap_generic.txt" \
  "-i"

  grepit_search "Generic sleep call, if server side this could block thread/process and therefore enable to easily do Denial of Service attacks" \
  'sleep(2);' \
  'FALSE_POSITIVES_EXAMPLE_PLACEHOLDER' \
  "sleep" \
  "7_general_sleep_generic.txt" \
  "-i"
}

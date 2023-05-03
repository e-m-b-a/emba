#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Benedikt Kuehne

# Description: Multiple useful helpers used to access online resources


# kernel downloader waits for s24 results. If we were able to identify a kernel version,
# a kernel config or at least kernel symbols we can use these details to verify the
# vulnerabilities which we identified based on the kernel version
kernel_downloader() {
  LOG_FILE_KERNEL="$CSV_DIR"/s24_kernel_bin_identifier.csv
  KERNEL_ARCH_PATH="$EXT_DIR"/linux_kernel_sources/

  if ! [[ -d "$KERNEL_ARCH_PATH" ]]; then
    mkdir "$KERNEL_ARCH_PATH"
  fi

  # we wait until the s24 module is finished and hopefully shows us a kernel version
  while ! [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; do
    sleep 1
  done
  if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
    while [[ $(grep -c S24_kernel_bin_identifier "$LOG_DIR"/"$MAIN_LOG_FILE") -lt 2 ]]; do
      sleep 1
    done
  fi

  # now we should have a csv log with a kernel version:
  if ! [[ -f "$LOG_FILE_KERNEL" ]]; then
    local OUTPUTTER="[-] No Kernel version identified ..."
    print_output "$OUTPUTTER" "no_log"
    write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"
    return
  fi
  local K_VERSIONS=()
  local K_VERSION=""

  mapfile -t K_VERSIONS < <(cut -d\; -f2 "$LOG_FILE_KERNEL" | tail -n +2 | sort -u | grep -E "[0-9]+(\.[0-9]+)+?" || true)

  for K_VERSION in "${K_VERSIONS[@]}"; do
    local OUTPUTTER="[*] Checking download of kernel version $ORANGE$K_VERSION$NC"
    print_output "$OUTPUTTER" "no_log"
    write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"
    local K_VER_DOWNLOAD=""
    local K_VER_1st=""
    local K_VER_2nd=""
    # local K_VER_3rd=""
  
    K_VER_1st=$(echo "$K_VERSION" | cut -d. -f1)
    K_VER_2nd=$(echo "$K_VERSION" | cut -d. -f2)
    # K_VER_3rd=$(echo "$K_VERSION" | cut -d. -f3)

    # prepare the path in the URL:
    if [[ "$K_VER_1st" -lt 3 ]]; then
      K_VER_DOWNLOAD="$K_VER_1st"".""$K_VER_2nd"
    elif [[ "$K_VER_1st" -eq 3 && "$K_VER_2nd" -eq 0 ]]; then
      K_VER_DOWNLOAD="$K_VER_1st"".""$K_VER_2nd"
    else
      K_VER_DOWNLOAD="$K_VER_1st"".x"
    fi

    # prepare the download filename:
    if [[ "$K_VERSION" == *".0" ]]; then
      # for download we need to modify versions like 3.1.0 to 3.1
      K_VERSION=${K_VERSION%.0}
    fi
  
    # we check if the sources archive is already available and is a valid tgz file:
    if ! [[ -f "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz ]] || ! gunzip -t "$KERNEL_ARCH_PATH/linux-$K_VERSION.tar.gz" > /dev/null; then
      local OUTPUTTER="[*] Kernel download for version $ORANGE$K_VERSION$NC"
      print_output "$OUTPUTTER" "no_log"
      write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"

      if ! [[ -d "$TMP_DIR" ]]; then
        mkdir "$TMP_DIR"
      fi

      disable_strict_mode "$STRICT_MODE" 0
      wget --output-file="$TMP_DIR"/wget.log https://mirrors.edge.kernel.org/pub/linux/kernel/v"$K_VER_DOWNLOAD"/linux-"$K_VERSION".tar.gz -O "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz 2>&1
      D_RETURN="$?"
      enable_strict_mode "$STRICT_MODE" 0

      if [[ -f "$TMP_DIR"/wget.log ]]; then
        print_ln
        tee -a "$LOG_DIR/kernel_downloader.log" < "$TMP_DIR"/wget.log
        rm "$TMP_DIR"/wget.log
      fi
      # if we have a non zero return something failed and we need to communicate this to the container modules (s26) which
      # checks for the file "$TMP_DIR"/linux_download_failed. If this file is available it stops waiting for the kernel
      # sources
      if [[ $D_RETURN -ne 0 ]] ; then
        local OUTPUTTER="[-] Kernel download for version $ORANGE$K_VERSION$NC failed"
        print_output "$OUTPUTTER" "no_log"
        write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"

        echo "failed" > "$TMP_DIR"/linux_download_failed
        if [[ -f "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz ]]; then
          rm "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz
        fi
      fi
    else
      local OUTPUTTER="[*] Kernel sources of version $ORANGE$K_VERSION$NC already available"
      print_output "$OUTPUTTER" "no_log"
      write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"
    fi
  
    if ! [[ -f "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz ]]; then
      local OUTPUTTER="[-] Kernel sources not available ..."
      print_output "$OUTPUTTER" "no_log"
      write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"
      continue
    fi
    if ! file "$KERNEL_ARCH_PATH"/linux-"$K_VERSION".tar.gz | grep -q "gzip compressed data"; then
      local OUTPUTTER="[-] Kernel sources not available ..."
      print_output "$OUTPUTTER" "no_log"
      write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"
      continue
    fi
    local OUTPUTTER="[*] Kernel source for version $ORANGE$K_VERSION$NC stored in $ORANGE$KERNEL_ARCH_PATH$NC"
    print_output "$OUTPUTTER" "no_log"
    write_log "$OUTPUTTER" "$LOG_DIR/kernel_downloader.log"
  done
}

# looks through the modules and finds chatgpt questions inside the csv
# (could be moved to embark)
ask_chatgpt(){
  export "$(grep -v '^#' "$CONFIG_DIR/gpt_config.env" | xargs || true )" # readin of all vars in that env file
  export CHATGPT_RESULT_CNT=0

  if [ -z "$OPENAI_API_KEY" ]; then
    print_output "[!] There is no API key in the config file"
    print_output "[!] Can't ask ChatGPT with this setup"
  else
    ask_chatgpt ./test-scripts  #TODO set this correctly, maybe from grepit?
    # TODO replace with simple wait?
  fi

  # default vars
  local GPT_QUESTION_="Please identify all vulnerabilities in this code: "
  local CHATGPT_CODE_=""
  local GPT_RESPONSE_=""
  local HTTP_CODE_=200

  # we wait until the s20 module is finished and hopefully has some code for us
  while ! [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; do
    sleep 10
  done
  if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
    while [[ $(grep -c S20_shell_check "$LOG_DIR"/"$MAIN_LOG_FILE") -lt 2 ]] && [[ $(grep -c S21_python_check "$LOG_DIR"/"$MAIN_LOG_FILE") -lt 2 ]] \
    && [[ $(grep -c S22_php_check "$LOG_DIR"/"$MAIN_LOG_FILE") -lt 2 ]] && [[ $(grep -c S24 "$LOG_DIR"/"$MAIN_LOG_FILE") -lt 2 ]] ; do
      sleep 1
    done
  fi

  print_output "[*] checking scripts with ChatGPT"

  local SCRIPT_FILE_TMP_=""
  local MINIMUM_GPT_PRIO=2
  local GPT_PRIO_=0

  while IFS=";" read -r COL1_ _COL2_ _COL3_ COL4_ COL5_ _COL6_ ; do
    GPT_QUESTION_="$COL5_"
    GPT_PRIO_="${COL4_//GPT-Prio-/}"
    SCRIPT_FILE_TMP_="$( echo "$COL1_" |  cut -d" " -f1 )"
    if [[ $GPT_PRIO_ -ge $MINIMUM_GPT_PRIO ]]; then
      # find realpath
      local TMP_PATH_=""
      TMP_PATH_=$(find "$FIRMWARE_PATH" -wholename "$SCRIPT_FILE_TMP_")
      if [ -f "$TMP_PATH_" ]; then
        print_output "Asking ChatGPT about $(print_path "$TMP_PATH_")"
        head -n -2 "$CONFIG_DIR/gpt_template.json" > "$TMP_DIR/chat.json"
        CHATGPT_CODE_=$(sed 's/"/\\\"/g' "$TMP_PATH_" | tr -d '[:space:]')
        printf '"%s %s"\n}]}' "$GPT_QUESTION_" "$CHATGPT_CODE_" >> "$TMP_DIR/chat.json"
        HTTP_CODE_=$(curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
          -H "Authorization: Bearer $OPENAI_API_KEY" \
          -d @"$TMP_DIR/chat.json" -o "$TMP_DIR/response.json" --write-out "%{http_code}")
        if [[ "$HTTP_CODE_" -ne 200 ]] ; then
          print_output "[!] Something went wrong with the ChatGPT requests"
          if [ -f "$TMP_DIR/response.json" ]; then
            print_output "ERROR response:$(cat "$TMP_DIR/response.json")"
          fi
        fi
        GPT_RESPONSE_=$(jq '.choices[] | .message.content' "$TMP_DIR"/response.json)
        printf '%s:%s;' "$FILE" "$GPT_RESPONSE_" >> "$CSV_DIR"/s111_gpt_check.csv
        print_output "Q:$GPT_QUESTION_ ($FILE) CHATGPT:$GPT_RESPONSE_"
        ((CHATGPT_RESULT_CNT++))
      fi
    fi
  done < <(grep "^/.*;GPT-Prio-.*;.*;NA;" "$CSV_DIR"/s2*.csv)  # get all paths from files from s20-s23
  
  
  # mapfile -t -O SCRIPT_FILE_TMP_ < <(grep "^/.*;GPT-Prio-$MINIMUM_GPT_PRIO;.*;NA;" "$CSV_DIR"/s20_shell_check.csv |  cut -d" " -f1 )
  unset OPENAI_API_KEY
}

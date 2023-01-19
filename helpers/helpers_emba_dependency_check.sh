#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check all dependencies for EMBA

DEP_ERROR=0 # exit EMBA after dependency check, if ONLY_DEP and FORCE both zero
DEP_EXIT=0  # exit EMBA after dependency check, regardless of which parameters have been set

# $1=File name
# $2=File path
check_dep_file()
{
  FILE_NAME="${1:-}"
  FILE_PATH="${2:-}"
  print_output "    ""$FILE_NAME"" - \\c" "no_log"
  if ! [[ -f "$FILE_PATH" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    Missing ""$FILE_NAME"" - check your installation""$NC"
    DEP_ERROR=1
  else
    echo -e "$GREEN""ok""$NC"
  fi
}

# $1=Tool title and command
# $2=Tool command, but only if set
check_dep_tool()
{
  TOOL_NAME="${1:-}"
  if [[ -n "${2:-}" ]] ; then
    TOOL_COMMAND="${2:-}"
  else
    TOOL_COMMAND="${1:-}"
  fi
  print_output "    ""$TOOL_NAME"" - \\c" "no_log"
  if ! command -v "$TOOL_COMMAND" > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    Missing ""$TOOL_NAME"" - check your installation""$NC"
    DEP_ERROR=1
  else
    echo -e "$GREEN""ok""$NC"
  fi
}

check_dep_port()
{
  TOOL_NAME="${1:-}"
  PORT_NR="${2:-}"
  print_output "    ""$TOOL_NAME"" - \\c" "no_log"
  if ! netstat -anpt | grep -q "$PORT_NR"; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    Missing ""$TOOL_NAME"" - check your installation""$NC"
    DEP_ERROR=1
  else
    echo -e "$GREEN""ok""$NC"
  fi
}

check_docker_env() {
  TOOL_NAME="MongoDB"
  print_output "    ""$TOOL_NAME"" - \\c" "no_log"
  if ! grep -q "bindIp: 172.36.0.1" /etc/mongod.conf; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    Wrong ""mongodb config"" - check your installation""$NC"
    echo -e "$RED""    RE-run installation - bindIp should be set to 172.36.0.1""$NC"
    DEP_ERROR=1
  else
    echo -e "$GREEN""ok""$NC"
  fi
  TOOL_NAME="Docker Interface"
  print_output "    ""$TOOL_NAME"" -""$RED"" \\c" "no_log"
  if ! ip a show emba_runs | grep -q "172.36.0.1" ; then
    echo -e "$RED""    Missing ""Docker-Interface"" - check your installation""$NC"
    if [[ "$WSL" -eq 1 ]]; then
      echo -e "$RED""    Is dockerd running (e.g., sudo dockerd --iptables=false &)""$NC"
      DEP_ERROR=1
    else
      if [[ $EUID -eq 0 ]]; then
        echo -e "$ORANGE""    Trying to auto-maintain the docker interface ...""$NC"
        systemctl restart NetworkManager docker
      fi
      if ! ip a show emba_runs | grep -q "172.36.0.1" ; then
        echo -e "$RED""    Use  \$systemctl restart NetworkManager docker or reset the docker interface manually (\$ docker network rm emba_runs)""$NC"
        DEP_ERROR=1
      else
        print_output "    ""$TOOL_NAME"" -""$RED"" \\c" "no_log"
        echo -e "$GREEN""ok""$NC"
      fi
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi
}

check_nw_interface() {
  if ! ip a show emba_runs | grep -q "172.36.0.1" ; then
    echo -e "$RED""    Network interface not available"" - trying to restart now""$NC"
    systemctl restart NetworkManager docker
    echo -e "$GREEN""    docker-networks restarted""$NC"
  fi
}

check_cve_search() {
  if [[ $JUMP_OVER_CVESEARCH_CHECK -eq 1 ]] ; then
    # no cve check -> just return and enforce CVE_SEARCH
    export CVE_SEARCH=1
    return
  fi
  TOOL_NAME="cve-search"
  print_output "    ""$TOOL_NAME"" - testing" "no_log"
  local CVE_SEARCH_=0 # local checker variable
  # check if the cve-search produces results:
  if ! [[ $("$PATH_CVE_SEARCH" -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
    # we can restart the mongod database only in dev mode and not in docker mode:
    if [[ "$IN_DOCKER" -eq 0 ]]; then
      print_output "[*] CVE-search not working - restarting Mongo database for CVE-search" "no_log"
      if [[ "$WSL" -eq 1 ]]; then
        pkill -f mongod
        mongod --config /etc/mongod.conf &
      else
        service mongod restart
      fi
      sleep 10

      # do a second try
      if ! [[ $("$PATH_CVE_SEARCH" -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
        print_output "[*] CVE-search not working - restarting Mongo database for CVE-search" "no_log"
        if [[ "$WSL" -eq 1 ]]; then
          pkill -f mongod
          mongod --config /etc/mongod.conf &
        else
          service mongod restart
        fi
        sleep 10

        if [[ $("$PATH_CVE_SEARCH" -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
          CVE_SEARCH_=1
        fi
      else
        CVE_SEARCH_=1
      fi
    else
      CVE_SEARCH_=1
    fi
  else
    CVE_SEARCH_=1
  fi

  if [[ "$CVE_SEARCH_" -eq 0 ]]; then
    print_output "    ""$TOOL_NAME"" - ""$RED""not ok""$NC" "no_log"
    print_cve_search_failure
    export CVE_SEARCH=0
  else
    print_output "    ""$TOOL_NAME"" - ""$GREEN""ok""$NC" "no_log"
    export CVE_SEARCH=1
  fi
}

print_cve_search_failure() {
  print_output "[-] The needed CVE database is not responding as expected." "no_log"
  print_output "[-] CVE checks are currently not possible!" "no_log"
  print_output "[-] Please check the following documentation on Github: https://github.com/e-m-b-a/emba/issues/187" "no_log"
  print_output "[-] If this does not help, open a new issue here: https://github.com/e-m-b-a/emba/issues" "no_log"
}

# Source: https://stackoverflow.com/questions/4023830/how-to-compare-two-strings-in-dot-separated-version-format-in-bash
version() { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

check_emulation_port() {
  TOOL_NAME="${1:-}"
  PORT_NR="${2:-}"
  print_output "    ""$TOOL_NAME"" - \\c" "no_log"
  if netstat -anpt | grep -q "$PORT_NR"; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    System emulation services detected - check for running Qemu processes""$NC"
  else
    echo -e "$GREEN""ok""$NC"
  fi
}

setup_nikto() {
  if [[ "$IN_DOCKER" -eq 1 ]] && [[ -d "$EXT_DIR"/var_lib_nikto ]]; then
    mkdir -p /var/lib/nikto
    cp -r "$EXT_DIR"/var_lib_nikto/nikto/* /var/lib/nikto/
  fi
}

setup_unblob() {
  TOOL_NAME="${1:-}"

  print_output "    ""$TOOL_NAME"" - \\c" "no_log"

  if command -v unblob; then
    echo -e "$GREEN""ok""$NC"
  elif ! command -v unblob && [[ -f "$EXT_DIR"/unblob/unblob_path.cfg ]]; then
    # recover unblob installation - usually we are in the docker container
    if ! [[ -d "$HOME"/.cache ]]; then
      mkdir "$HOME"/.cache
    fi
    if [[ "$IN_DOCKER" -eq 1 ]]; then
      if [[ -d "$EXT_DIR"/unblob/root_cache ]]; then
        cp -pr "$EXT_DIR"/unblob/root_cache/* "$HOME"/.cache/
      else
        echo -e "$RED""not ok""$NC"
        DEP_EXIT=1
      fi
    fi
    if [[ -e $(cat "$EXT_DIR"/unblob/unblob_path.cfg)/bin/"$UNBLOB_BIN" ]]; then
      UNBLOB_PATH="$(cat "$EXT_DIR"/unblob/unblob_path.cfg)""/bin/"
      export PATH=$PATH:"$UNBLOB_PATH"
      echo -e "$GREEN""ok""$NC"
    else
      echo -e "$RED""not ok""$NC"
      DEP_EXIT=1
    fi
  else
    echo -e "$RED""not ok""$NC"
    DEP_EXIT=1
  fi
  print_output "    ""sasquatch"" - \\c" "no_log"
  if [[ -f /usr/local/bin/sasquatch_binwalk ]]; then
    if [[ -L "$UNBLOB_PATH"/sasquatch ]]; then
      rm  "$UNBLOB_PATH"/sasquatch
    fi
    ln -s /usr/local/bin/sasquatch_binwalk "$UNBLOB_PATH"/sasquatch
    echo -e "$GREEN""ok""$NC"
  elif [[ -f /usr/local/bin/sasquatch_unblob ]]; then
    if [[ -L "$UNBLOB_PATH"/sasquatch ]]; then
      rm  "$UNBLOB_PATH"/sasquatch
    fi
    ln -s /usr/local/bin/sasquatch_unblob "$UNBLOB_PATH"/sasquatch
    echo -e "$ORANGE""warning""$NC"
    DEP_EXIT=1
  else
    echo -e "$RED""not ok""$NC"
    DEP_EXIT=1
  fi
}

dependency_check() 
{
  module_title "Dependency check" "no_log"

  print_ln "no_log"
  #######################################################################################
  # Elementary checks
  #######################################################################################
  print_output "[*] Elementary:" "no_log"

  # currently we need root privileges for emulation and multiple extractors
  # As the container runs as root we should not run into issues within the container.
  # Outside the container we can run mostly without root privs - this is currently under evaluation
  # Some other nice features like restarting the mongod will not work without root privs.
  print_output "    user permissions" "no_log"
  if [[ $QEMULATION -eq 1 && $EUID -ne 0 ]] || [[ $USE_DOCKER -eq 1 && $EUID -ne 0 ]] || [[ $FULL_EMULATION -eq 1 && $EUID -ne 0 ]]; then
    if [[ $QEMULATION -eq 1 && $USE_DOCKER -eq 0 ]] || [[ $FULL_EMULATION -eq 1 && $USE_DOCKER -eq 0 ]]; then
      print_output "    user permission - emulation mode - \\c" "no_log"
      echo -e "$RED""not ok""$NC"
      echo -e "$RED""    With emulation enabled this script needs root privileges""$NC"
      DEP_EXIT=1
    else
      print_output "    user permission - emulation mode - \\c" "no_log"
      echo -e "$GREEN""ok""$NC"
    fi
    if [[ $USE_DOCKER -eq 1 ]]; then
      print_output "    user permission - docker mode - \\c" "no_log"
      if ! groups | grep -qw docker; then
        echo -e "$RED""not ok""$NC"
        echo -e "$RED""   With docker enabled this script needs privileges to start the docker container""$NC"
        echo -e "$RED""   Run EMBA with root permissions or add your user to docker group""$NC"
        echo -e "$RED""   e.g., sudo usermod -aG docker [non-root user]""$NC"
        DEP_EXIT=1
      else
        echo -e "$GREEN""ok""$NC"
      fi
    fi
  else
    print_output "    user permission - \\c" "no_log"
    echo -e "$GREEN""ok""$NC"
  fi

  # EMBA is developed for and on KALI Linux
  # In our experience we can say that it runs on most Debian based systems without any problems 
  if [[ $USE_DOCKER -eq 0 ]] ; then
    print_output "    host distribution - \\c" "no_log"
    if grep -q "kali" /etc/debian_version 2>/dev/null ; then
      echo -e "$GREEN""ok""$NC"
    elif grep -qEi "debian|buntu|mint" /etc/*release 2>/dev/null ; then
      echo -e "$ORANGE""ok""$NC"
      echo -e "$ORANGE""    This script is only tested on KALI Linux, but should run fine on most Debian based distros""$NC" 1>&2
    else
      echo -e "$RED""not ok""$NC"
      echo -e "$RED""    This script is only tested on KALI Linux""$NC" 1>&2
    fi
  fi

  # Check for ./config
  print_output "    configuration directory - \\c" "no_log"
  if ! [[ -d "$CONFIG_DIR" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    Missing configuration directory - check your installation""$NC"
    DEP_ERROR=1
  else
    echo -e "$GREEN""ok""$NC"
  fi

  # Check for ./external
  if [[ $USE_DOCKER -eq 0 ]] ; then
    print_output "    external directory - \\c" "no_log"
    if ! [[ -d "$EXT_DIR" ]] ; then
      echo -e "$RED""not ok""$NC"
      echo -e "$RED""    Missing configuration directory for external programs - check your installation""$NC"
      DEP_ERROR=1
    else
      echo -e "$GREEN""ok""$NC"
    fi
  fi


  print_ln "no_log"
  print_output "[*] Necessary utils on system:" "no_log"

  #######################################################################################
  # Docker for EMBA with docker
  #######################################################################################
  if [[ $USE_DOCKER -eq 1 ]] ; then
    check_dep_tool "docker"
    check_dep_tool "docker-compose"
    check_docker_env
    check_cve_search
    check_dep_tool "inotifywait"
    check_dep_tool "notify-send"
  fi

  #######################################################################################
  # Check system tools
  #######################################################################################
  if [[ $USE_DOCKER -eq 0 ]] ; then
    SYSTEM_TOOLS=("awk" "basename" "bash" "cat" "chmod" "chown" "cp" "cut" "date" "dirname" \
      "dpkg-deb" "echo" "eval" "find" "grep" "head" "kill" "ln" "ls" "md5sum" "mkdir" "mknod" \
      "modinfo" "mv" "netstat" "openssl" "printf" "pwd" "readelf" "realpath" "rm" "rmdir" "sed" \
      "seq" "sleep" "sort" "strings" "tee" "touch" "tr" "uniq" "unzip" "wc")

    for TOOL in "${SYSTEM_TOOLS[@]}" ; do
      check_dep_tool "$TOOL"
      if [[ "$TOOL" == "bash" ]] ; then
        # using bash higher than v4
        print_output "    bash (version): ""${BASH_VERSINFO[0]}"" - \\c" "no_log"
        if ! [[ "${BASH_VERSINFO[0]}" -gt 3 ]] ; then
          echo -e "$RED""not ok""$NC"
          echo -e "$RED""    Upgrade your bash to version 4 or higher""$NC"
          DEP_ERROR=1
        else
          echo -e "$GREEN""ok""$NC"
        fi
      fi
    done 


    #######################################################################################
    # Check external tools
    #######################################################################################

    print_ln "no_log"
    print_output "[*] External utils:" "no_log"

    # bc
    check_dep_tool "bc"

    # tree
    check_dep_tool "tree"

    # unzip
    check_dep_tool "unzip"

    # 7zip
    check_dep_tool "7z"

    # jchroot - https://github.com/vincentbernat/jchroot
    check_dep_tool "jchroot"

    # mkimage (uboot)
    check_dep_tool "uboot mkimage" "mkimage"

    # binwalk
    check_dep_tool "binwalk extractor" "binwalk"
    if command -v binwalk > /dev/null ; then
      BINWALK_VER=$(binwalk 2>&1 | grep "Binwalk v" | cut -d+ -f1 | awk '{print $2}' | sed 's/^v//' || true)
      if ! [ "$(version "$BINWALK_VER")" -ge "$(version "2.3.3")" ]; then
        echo -e "$ORANGE""    binwalk version $BINWALK_VER - not optimal""$NC"
        echo -e "$ORANGE""    Upgrade your binwalk to version 2.3.3 or higher""$NC"
        export BINWALK_VER_CHECK=0
      else
        export BINWALK_VER_CHECK=1
      fi
      # this is typically needed in the read only docker container:
      if ! [[ -d "$HOME"/.config/binwalk/modules/ ]]; then
        mkdir -p "$HOME"/.config/binwalk/modules/
      fi
      print_output "    cpu_rec - \\c" "no_log"
      if [[ -d "$EXT_DIR"/cpu_rec/ ]]; then
        cp -pr "$EXT_DIR"/cpu_rec/cpu_rec.py "$HOME"/.config/binwalk/modules/
        cp -pr "$EXT_DIR"/cpu_rec/cpu_rec_corpus "$HOME"/.config/binwalk/modules/
        echo -e "$GREEN""ok""$NC"
      else
        echo -e "$RED""not ok""$NC"
        # DEP_ERROR=1
      fi
    fi
    export MPLCONFIGDIR="$TMP_DIR"

    setup_unblob "unblob"
    check_dep_tool "unrar" "unrar"
    setup_nikto

    # jtr
    check_dep_tool "john"

    # pixd
    check_dep_file "pixd visualizer" "$EXT_DIR""/pixde"

    # php iniscan
    check_dep_file "PHP iniscan" "$EXT_DIR""/iniscan/vendor/bin/iniscan"

    # pixd image
    check_dep_file "pixd image renderer" "$EXT_DIR""/pixd_png.py"

    # progpilot for php code checks
    check_dep_file "progpilot php ini checker" "$EXT_DIR""/progpilot"

    # patool extractor - https://wummel.github.io/patool/
    check_dep_tool "patool"

    # Freetz-NG
    check_dep_file "Freetz-NG fwmod" "$EXT_DIR""/freetz-ng/fwmod"

    # AVM fitimg extraction script
    check_dep_file "fitimg script" "$EXT_DIR""/fitimg-0.8/fitimg"

    # EnGenius decryptor - https://gist.github.com/ryancdotorg/914f3ad05bfe0c359b79716f067eaa99
    check_dep_file "EnGenius decryptor" "$EXT_DIR""/engenius-decrypt.py"

    # Android payload.bin extractor
    check_dep_file "Android payload.bin extractor" "$EXT_DIR""/payload_dumper/payload_dumper.py"

    check_dep_file "QNAP decryptor" "$EXT_DIR""/PC1"

    check_dep_file "Buffalo decryptor" "$EXT_DIR""/buffalo-enc.elf"

    check_dep_tool "ubireader image extractor" "ubireader_extract_images"
    check_dep_tool "ubireader file extractor" "ubireader_extract_files"
    
    # UEFI
    check_dep_tool "UEFI image extractor" "$EXT_DIR""/UEFITool/UEFIExtract"
    
    if function_exists F20_vul_aggregator; then
      # CVE-search
      # TODO change to portcheck and write one for external hosts
      check_dep_file "cve-search script" "$EXT_DIR""/cve-search/bin/search.py"
      # we have already checked it outside the docker - do not need it again
      if [[ "$IN_DOCKER" -eq 0 ]]; then
        check_cve_search
      fi
      if [[ "$IN_DOCKER" -eq 0 ]]; then
        # really basic check, if cve-search database is running - no check, if populated and also no check, if EMBA in docker
        check_dep_tool "mongo database" "mongod"
        # check_cve_search
      fi
      # CVE searchsploit
      check_dep_tool "CVE Searchsploit" "cve_searchsploit"

      check_dep_file "Routersploit EDB database" "$CONFIG_DIR""/routersploit_exploit-db.txt"
      check_dep_file "Routersploit CVE database" "$CONFIG_DIR""/routersploit_cve-db.txt"
      check_dep_file "Metasploit CVE database" "$CONFIG_DIR""/msf_cve-db.txt"
    fi

    # checksec
    check_dep_file "checksec script" "$EXT_DIR""/checksec"

    # sshdcc
    check_dep_file "sshdcc script" "$EXT_DIR""/sshdcc"

    # sudo-parser.pl
    check_dep_file "sudo-parser script" "$EXT_DIR""/sudo-parser.pl"

    # sh3llcheck - I know it's a typo, but this particular tool nags about it
    check_dep_tool "shellcheck script" "shellcheck"

    # fdtdump (device tree compiler)
    export DTBDUMP
    DTBDUMP_M="$(check_dep_tool "fdtdump" "fdtdump")"
    if echo "$DTBDUMP_M" | grep -q "not ok" ; then
      DTBDUMP=0
    else
      DTBDUMP=1
    fi
    echo -e "$DTBDUMP_M"

    # linux-exploit-suggester.sh script
    check_dep_file "linux-exploit-suggester.sh script" "$EXT_DIR""/linux-exploit-suggester.sh"

    if function_exists S13_weak_func_check; then
      # objdump
      OBJDUMP="$EXT_DIR""/objdump"
      check_dep_file "objdump disassembler" "$OBJDUMP"
    fi

    if function_exists S14_weak_func_radare_check; then
      # radare2
      check_dep_tool "radare2" "r2"
    fi

    # bandit python security tester
    check_dep_tool "bandit - python vulnerability scanner" "bandit"

    # qemu
    check_dep_tool "qemu-[ARCH]-static" "qemu-mips-static"

    # yara
    check_dep_tool "yara"

    # cyclonedx - converting csv sbom to json sbom
    if [[ -d "/home/linuxbrew/.linuxbrew/bin/" ]]; then
      export PATH=$PATH:/home/linuxbrew/.linuxbrew/bin/
    fi
    if [[ -d "/home/linuxbrew/.linuxbrew/Cellar/cyclonedx-cli/0.24.0.reinstall/bin/" ]]; then
      # check this - currently cyclone is installed in this dir in our docker image:
      export PATH=$PATH:/home/linuxbrew/.linuxbrew/Cellar/cyclonedx-cli/0.24.0.reinstall/bin/
    fi
    check_dep_tool "cyclonedx"

    check_dep_file "vmlinux-to-elf" "$EXT_DIR""/vmlinux-to-elf/vmlinux-to-elf"

    if function_exists S108_stacs_password_search; then
      # stacs - https://github.com/stacscan/stacs
      check_dep_tool "STACS hash detection" "stacs"
    fi

    # Full system emulation modules (L*)
    if [[ $FULL_EMULATION -eq 1 ]]; then
      check_dep_tool "Qemu system emulator ARM" "qemu-system-arm"
      check_dep_tool "Qemu system emulator ARM64" "qemu-system-aarch64"
      check_dep_tool "Qemu system emulator MIPS" "qemu-system-mips"
      check_dep_tool "Qemu system emulator MIPSel" "qemu-system-mipsel"
      check_dep_tool "Qemu system emulator MIPS64" "qemu-system-mips64"
      check_dep_tool "Qemu system emulator MIPS64el" "qemu-system-mips64el"
      check_dep_tool "Qemu system emulator NIOS2" "qemu-system-nios2"
      check_dep_tool "Qemu system emulator x86" "qemu-system-x86_64"
      # check_dep_tool "Qemu system emulator RISC-V" "qemu-system-riscv32"
      # check_dep_tool "Qemu system emulator RISC-V64" "qemu-system-riscv64"

      # check only some of the needed files
      check_dep_file "console.*" "$EXT_DIR""/EMBA_Live_bins/console.x86el"
      check_dep_file "busybox.*" "$EXT_DIR""/EMBA_Live_bins/busybox.mipsel"
      check_dep_file "libnvram.*" "$EXT_DIR""/EMBA_Live_bins/libnvram.so.armel"
      check_dep_file "libnvram_ioctl.*" "$EXT_DIR""/EMBA_Live_bins/libnvram_ioctl.so.mips64v1el"
      check_dep_file "vmlinux.mips*" "$EXT_DIR""/EMBA_Live_bins/vmlinux.mips64r2el.4"
      check_dep_file "zImage.armel" "$EXT_DIR""/EMBA_Live_bins/zImage.armel"

      check_dep_file "fixImage.sh" "$MOD_DIR""/L10_system_emulation/fixImage.sh"
      check_dep_file "preInit.sh" "$MOD_DIR""/L10_system_emulation/preInit.sh"
      check_dep_file "inferFile.sh" "$MOD_DIR""/L10_system_emulation/inferFile.sh"
      check_dep_file "inferService.sh" "$MOD_DIR""/L10_system_emulation/inferService.sh"

      # routersploit for full system emulation
      check_dep_file "Routersploit installation" "$EXT_DIR""/routersploit/rsf.py"

      check_dep_file "Arachni web scanner installation" "$EXT_DIR""/arachni/arachni-1.6.1.3-0.6.1.1/bin/arachni"
      check_dep_file "TestSSL.sh installation" "$EXT_DIR""/testssl.sh/testssl.sh"
      check_dep_tool "Nikto web server analyzer" "nikto"
      check_dep_tool "Cutycapt screenshot tool" "cutycapt"
      check_dep_tool "snmp-check tool" "snmp-check"
      check_dep_tool "Nmap portscanner" "nmap"
      check_dep_tool "hping3" "hping3"
      check_dep_tool "ping" "ping"
      check_dep_tool "Metasploit framework" "msfconsole"
      # This port is used by our Qemu installation and should not be used by another process.
      # This check is not a blocker for the test. It is checked again by the emulation module:
      check_emulation_port "Running Qemu network service" "2001"
      # Port 4321 is used for Qemu telnet access and should be available
      check_emulation_port "Running Qemu telnet service" "4321"
    fi

    if [[ "$CWE_CHECKER" -eq 1 ]]; then
      print_output "    cwe-checker environment - \\c" "no_log"
      if [[ -f "$EXT_DIR""/cwe_checker/bin/cwe_checker" ]] || [[ -f "/root/.cargo/bin/cwe_checker" ]]; then
        echo -e "$GREEN""ok""$NC"
      else
        echo -e "$RED""not ok""$NC"
        echo -e "$RED""    Missing cwe-checker start script - check your installation""$NC"
        export CWE_CHECKER=0
        DEP_ERROR=1
      fi
    fi
  fi
  

  if [[ $DEP_ERROR -gt 0 ]] || [[ $DEP_EXIT -gt 0 ]]; then
    print_output "\\n""$ORANGE""Some dependencies are missing - please check your installation\\n" "no_log"
    if [[ "$IN_DOCKER" -eq 1 ]]; then
      print_output "$ORANGE""Looks like your docker container is outdated - please update your base image: ""$NC""sudo docker pull embeddedanalyzer/emba""$ORANGE""'." "no_log"
    else
      print_output "$ORANGE""To install all needed dependencies, run '""$NC""sudo ./installer.sh""$ORANGE""'." "no_log"
      print_output "$ORANGE""Learn more about the installation on the EMBA wiki: ""$NC""https://github.com/e-m-b-a/emba/wiki/installation\\n" "no_log"
    fi

    if [[ $ONLY_DEP -eq 1 ]] || [[ $FORCE -eq 0 ]] || [[ $DEP_EXIT -gt 0 ]]; then
      exit 1
    fi
  else
    print_output "\\n" "no_log"
  fi

  # If only dependency check, then exit EMBA after it
  if [[ $ONLY_DEP -eq 1 ]]; then
    if [[ "$IN_DOCKER" -eq 1 ]] || [[ "$USE_DOCKER" -eq 0 ]]; then
      exit 0
    fi
    # no exit if USE_DOCKER -eq 1 and not in docker -> IN_DOCKER -eq 0
  fi
}

architecture_dep_check() {
  print_ln "no_log"
  local ARCH_STR="unknown"
  if [[ "$ARCH" == "MIPS" ]] ; then
    ARCH_STR="mips"
  elif [[ "$ARCH" == "MIPS64R2" ]] ; then
    ARCH_STR="mips64r2"
  elif [[ "$ARCH" == "MIPS64_III" ]] ; then
    ARCH_STR="mips64_III"
  elif [[ "$ARCH" == "MIPS64N32" ]] ; then
    ARCH_STR="mips64n32"
  elif [[ "$ARCH" == "MIPS64v1" ]] ; then
    ARCH_STR="mips64v1"
  elif [[ "$ARCH" == "ARM" ]] ; then
    ARCH_STR="arm"
  elif [[ "$ARCH" == "ARM64" ]] ; then
    ARCH_STR="aarch64"
  elif [[ "$ARCH" == "x86" ]] ; then
    ARCH_STR="i386"
  elif [[ "$ARCH" == "x64" ]] ; then
    # ARCH_STR="i386:x86-64"
    ARCH_STR="x86-64"
  elif [[ "$ARCH" == "PPC" ]] ; then
    # ARCH_STR="powerpc:common"
    ARCH_STR="powerpc"
  elif [[ "$ARCH" == "PPC64" ]] ; then
    ARCH_STR="powerpc64"
  elif [[ "$ARCH" == "NIOS2" ]] ; then
    ARCH_STR="nios2"
  elif [[ "$ARCH" == "RISCV" ]] ; then
    ARCH_STR="riscv"
  elif [[ "$ARCH" == "QCOM_DSP6" ]] ; then
    ARCH_STR="qcom_dsp6"
  else
    ARCH_STR="unknown"
  fi
  if [[ "$ARCH_STR" == "unknown" ]] ; then
    print_output "[-] WARNING: No valid architecture detected\\n" "no_log"
  else
    print_output "[+] ""$ARCH"" is a valid architecture\\n" "no_log"
  fi
}

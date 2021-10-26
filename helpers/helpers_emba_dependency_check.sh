#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check all dependencies for emba

DEP_ERROR=0 # exit emba after dependency check, if ONLY_DEP and FORCE both zero
DEP_EXIT=0  # exit emba after dependency check, regardless of which parameters have been set

# $1=File name
# $2=File path
check_dep_file()
{
  FILE_NAME="$1"
  FILE_PATH="$2"
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
  TOOL_NAME="$1"
  if [[ -n "$2" ]] ; then
    TOOL_COMMAND="$2"
  else
    TOOL_COMMAND="$1"
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
  TOOL_NAME="$1"
  PORT_NR="$2"
  print_output "    ""$TOOL_NAME"" - \\c" "no_log"
  if ! netstat -anpt | grep -q "$PORT_NR"; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    Missing ""$TOOL_NAME"" - check your installation""$NC"
    DEP_ERROR=1
  else
    echo -e "$GREEN""ok""$NC"
  fi
}

# Source: https://stackoverflow.com/questions/4023830/how-to-compare-two-strings-in-dot-separated-version-format-in-bash
version() { echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'; }

dependency_check() 
{
  module_title "Dependency check" "no_log"

  echo
  #######################################################################################
  # Elementary checks
  #######################################################################################
  print_output "[*] Elementary:" "no_log"

  # currently we only need root privileges for emulation
  # but we are running into issues if we have already run an emulation test with root privs
  # and try to run an non emulation test afterwards on the same log directory
  print_output "    user permission - \\c" "no_log"
  if [[ $QEMULATION -eq 1 && $EUID -ne 0 ]] || [[ $USE_DOCKER -eq 1 && $EUID -ne 0 ]]; then
    echo -e "$RED""not ok""$NC"
    if [[ $QEMULATION -eq 1 ]]; then
      echo -e "$RED""    With emulation enabled this script needs root privileges""$NC"
    fi
    if [[ $USE_DOCKER -eq 1 ]]; then
      echo -e "$RED""    With docker enabled this script needs root privileges""$NC"
    fi
    echo -e "$RED""    Run emba with sudo""$NC"
    DEP_EXIT=1
  else
    echo -e "$GREEN""ok""$NC"
  fi

  # emba is developed for and on KALI Linux
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


  echo
  print_output "[*] Necessary utils on system:" "no_log"

  #######################################################################################
  # Docker for emba with docker
  #######################################################################################
  if [[ $USE_DOCKER -eq 1 ]] ; then
    check_dep_tool "docker"
    check_dep_tool "docker-compose"
    check_dep_port "cve-search" 27017
    if ! netstat -anpt | grep -q 27017; then
      sudo mongod restart
      check_dep_port "cve-search" 27017
    fi
  fi

  #######################################################################################
  # Check system tools
  #######################################################################################
  if [[ $USE_DOCKER -eq 0 ]] ; then
    SYSTEM_TOOLS=("awk" "basename" "bash" "cat" "chmod" "chown" "cp" "cut" "date" "dirname" "dpkg-deb" "echo" "eval" "find" "grep" "head" "kill" "ln" "ls" "md5sum" "mkdir" "mknod" "modinfo" "mv" "netstat" "openssl" "printf" "pwd" "readelf" "realpath" "rm" "rmdir" "sed" "seq" "sleep" "sort" "strings" "tee" "touch" "tr" "uniq" "unzip" "wc")

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

    echo
    print_output "[*] External utils:" "no_log"
  
    # bc
    check_dep_tool "bc"

    # binwalk
    check_dep_tool "binwalk"
    if command -v binwalk > /dev/null ; then
      BINWALK_VER=$(binwalk 2>&1 | grep "Binwalk v" | cut -d+ -f1 | awk '{print $2}' | sed 's/^v//')
      if ! [ "$(version "$BINWALK_VER")" -ge "$(version "2.3.3")" ]; then
        echo -e "$RED""    binwalk version - not ok""$NC"
        echo -e "$RED""    Upgrade your binwalk to version 2.3.3 or higher""$NC"
        DEP_ERROR=1
      fi
    fi

    # checksec
    check_dep_file "checksec script" "$EXT_DIR""/checksec"

    # sshdcc
    check_dep_file "sshdcc script" "$EXT_DIR""/sshdcc"

    # sudo-parser.pl
    check_dep_file "sudo-parser script" "$EXT_DIR""/sudo-parser.pl"

    # pixd
    check_dep_file "pixd visualizer" "$EXT_DIR""/pixde"

    # pixd image
    check_dep_file "pixd image renderer" "$EXT_DIR""/pixd_png.py"

    # progpilot for php code checks
    check_dep_file "progpilot php checker" "$EXT_DIR""/progpilot"

    # CVE and CVSS databases
    check_dep_file "CVE database" "$EXT_DIR""/allitems.csv"
    check_dep_file "CVSS database" "$EXT_DIR""/allitemscvss.csv"

    # CVE-search
    check_dep_file "cve-search" "$EXT_DIR""/cve-search/bin/search.py"
    if [[ IN_DOCKER -eq 0 ]]; then 
      # really basic check, if cve-search database is running - no check, if populated and also no check, if emba in docker
      check_dep_tool "mongoDB" "mongod"
      check_dep_port "cve-search" 27017
    fi

    # firmadyne
    if [[ $FULL_EMULATION -eq 1 ]]; then
      # check only some of the needed files
      check_dep_file "console.mipsel" "$EXT_DIR""/firmadyne/binaries/console.mipsel"
      check_dep_file "vmlinux.mipseb" "$EXT_DIR""/firmadyne/binaries/vmlinux.mipseb"
      check_dep_file "fixImage.sh" "$EXT_DIR""/firmadyne/scripts/fixImage.sh"
      check_dep_file "preInit.sh" "$EXT_DIR""/firmadyne/scripts/preInit.sh"
      check_dep_tool "qemu-system-arm"
      check_dep_tool "qemu-system-mips"
      check_dep_tool "qemu-system-mipsel"
    fi

    # CVE searchsploit
    check_dep_tool "CVE Searchsploit" "cve_searchsploit"


    # Check if fact extractor is on the system - disable, if not
    export FACT_EXTRACTOR=1 

    print_output "    fact-extractor start script - \\c" "no_log"
    if [[ -f "$EXT_DIR""/fact_extractor/fact_extractor/fact_extract.py" ]] ; then
      echo -e "$GREEN""ok""$NC"
    else
      echo -e "$RED""not ok""$NC"
      echo -e "$RED""    Missing fact-extractor start script - check your installation""$NC"
      FACT_EXTRACTOR=0
      DEP_ERROR=1
    fi

    print_output "    cwe-checker environment - \\c" "no_log"
    if [[ -f "$EXT_DIR""/cwe_checker/bin/cwe_checker" ]] ; then
      echo -e "$GREEN""ok""$NC"
    else
      echo -e "$RED""not ok""$NC"
      echo -e "$RED""    Missing cwe-checker start script - check your installation""$NC"
      FACT_EXTRACTOR=0
      DEP_ERROR=1
    fi
 
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

    # objdump
    OBJDUMP="$EXT_DIR""/objdump"
    check_dep_file "objdump" "$OBJDUMP"

    # php
    check_dep_tool "php"

    # pylint
    check_dep_tool "pylint"

    # qemu
    check_dep_tool "qemu-[ARCH]-static" "qemu-mips-static"

    # sh3llcheck - I know it's a typo, but this particular tool nags about it
    check_dep_tool "shellcheck"

    # tree
    check_dep_tool "tree"

    # unzip
    check_dep_tool "unzip"

    # yara
    check_dep_tool "yara"
  fi
  
  if [[ $DEP_ERROR -gt 0 ]] || [[ $DEP_EXIT -gt 0 ]]; then
    print_output "\\n""$ORANGE""Some dependencies are missing - please check your installation\\n" "no_log"
    print_output "$ORANGE""To install all needed dependencies, run '""$NC""sudo ./installer.sh""$ORANGE""'." "no_log"
    print_output "$ORANGE""Learn more about the installation on the emba wiki: ""$NC""https://github.com/e-m-b-a/emba/wiki/installation\\n" "no_log"

    if { [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ;} || [[ $DEP_EXIT -gt 0 ]] ; then
      exit 1
    fi
  else
    print_output "\\n" "no_log"
  fi

  # If only dependency check, then exit emba after it
  if [[ $ONLY_DEP -eq 1 ]] ; then
    exit 0
  fi
  
}

architecture_dep_check() {
  echo
  if [[ "$ARCH" == "MIPS" ]] ; then
    ARCH_STR="mips"
  elif [[ "$ARCH" == "ARM" ]] ; then
    ARCH_STR="arm"
  elif [[ "$ARCH" == "x86" ]] ; then
    ARCH_STR="i386"
  elif [[ "$ARCH" == "x64" ]] ; then
    #ARCH_STR="i386:x86-64"
    ARCH_STR="x86-64"
  elif [[ "$ARCH" == "PPC" ]] ; then
    #ARCH_STR="powerpc:common"
    ARCH_STR="powerpc"
  fi
  if [[ -z "$ARCH_STR" ]] ; then
    print_output "[-] ""$ARCH"" isn't a valid architecture - exit emba\\n" "no_log"
    exit 1
  else
    print_output "[+] ""$ARCH"" is a valid architecture\\n" "no_log"
  fi
}

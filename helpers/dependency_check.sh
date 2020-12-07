#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check all dependencies for emba


dependency_check() 
{
  module_title "Dependency check" "no_log"

  echo
  print_output "[*] Elementary checks:" "no_log"

  print_output "    user permission - \\c" "no_log"
  if [[ $EUID -eq 0 ]] ; then
    echo -e "$GREEN""ok""$NC"
  else
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""This script should be used as root user""$NC"
  fi

  print_output "    host distribution - \\c" "no_log"
  if grep -q "kali" /etc/debian_version 2>/dev/null ; then
    echo -e "$GREEN""ok""$NC"
  else
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    This script is only tested on KALI linux""$NC" 1>&2
  fi

  if [[ $ONLY_DEP -eq 1 ]] && [[ -z "$ARCH" ]] || [[ "$PRE_CHECK" -eq 1 ]]; then
    print_output "    architecture - ""$ORANGE""not checked""$NC" "no_log"
  elif [[ $FIRMWARE -eq 1 ]] || { [[ $ONLY_DEP -eq 1 ]] && [[ -n "$ARCH" ]] ; } ; then
    print_output "    architecture - \\c" "no_log"
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
      echo -e "$RED""not ok""$NC"
      echo -e "$RED""    wrong architecture""$NC"
      if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
        exit 1
      fi
    else
      echo -e "$GREEN""ok""$NC"
    fi
  fi

  print_output "    configuration directory - \\c" "no_log"
  if ! [[ -d "$CONFIG_DIR" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing configuration directory ... check your installation""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    external directory - \\c" "no_log"
  if ! [[ -d "$EXT_DIR" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing configuration directory for external programs ... check your installation""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi



  echo
  print_output "[*] Necessary utils on system checks:" "no_log"

  print_output "    basename - \\c" "no_log"
  if ! command -v basename > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing basename binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  # using bash higher than v4 ...
  print_output "    bash (version) - \\c" "no_log"
  BASH_VERSION="$(config_grep_string "$CONFIG_DIR""/version_strings.cfg" "$(bash --version)")"
  if ! [[ "${BASH_VERSINFO[0]}" -gt 3 ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    upgrade your bash to version 4 or higher""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    cut - \\c" "no_log"
  if ! command -v cut > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing cut binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    find - \\c" "no_log"
  if ! command -v find > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing find binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    grep - \\c" "no_log"
  if ! command -v grep > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing grep binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    modinfo - \\c" "no_log"
  if ! command -v  modinfo > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing modinfo binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    readelf - \\c" "no_log"
  READELF=$(command -v readelf)
  # check for needed dependencies:
  if ! [[ -x "$READELF" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing readelf binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    realpath - \\c" "no_log"
  if ! command -v  realpath > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing realpath binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    sed - \\c" "no_log"
  if ! command -v sed > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing sed binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    sort - \\c" "no_log"
  if ! command -v sort > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing sort binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    strings - \\c" "no_log"
  if ! command -v strings > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing strings binary""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi



  echo
  print_output "[*] Optional utils checks:" "no_log"

  print_output "    checksec script - \\c" "no_log"
  if ! [[ -f "$EXT_DIR""/checksec" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing checksec ... check your installation""$NC"
    echo -e "$RED""    you can run the installer.sh script or download it manually:""$NC"
    echo -e "$RED""      https://github.com/slimm609/checksec.sh""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  if [[ $BAP -eq 1 ]] ; then
    print_output "    docker - \\c" "no_log"
    if ! command -v docker > /dev/null ; then
      echo -e "$RED""not ok""$NC"
      echo -e "$RED""    missing docker ... check your installation""$NC"
      echo -e "$RED""    you can run the installer.sh script or install it manually""$NC"
      BAP=0
    else
      echo -e "$GREEN""ok""$NC"
      print_output "    cwe-checker - \\c" "no_log"
      if docker images | grep -q cwe_checker ; then
        echo -e "$GREEN""ok""$NC"
      else
        echo -e "$RED""not ok""$NC"
        echo -e "$RED""    missing docker image cwe-checker ... check your installation""$NC"
        echo -e "$RED""      https://github.com/fkie-cad/cwe_checker""$NC"
        echo -e "$RED""    you can run the installer.sh script or pull it manually:""$NC"
        echo -e "$RED""      docker pull fkiecad/cwe_checker:latest""$NC"
        BAP=0
      fi
    fi
  else
    print_output "    docker and cwe-checker - \\c" "no_log"
    echo -e "$ORANGE""not checked (disabled)""$NC"
  fi

  print_output "    fdtdump - \\c" "no_log"
  if ! command -v fdtdump > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    fdtdump not found ... disabling tests""$NC"
    echo -e "$RED""    install fdtdump via apt-get install device-tree-compiler""$NC"
    DTBDUMP=0
  else
    echo -e "$GREEN""ok""$NC"
    DTBDUMP=1
  fi
  export DTBDUMP

  print_output "    linux-exploit-suggester.sh script - \\c" "no_log"
  if ! [[ -f "$EXT_DIR""/linux-exploit-suggester.sh" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing linux-exploit-suggester.sh ... check your installation""$NC"
    echo -e "$RED""    you can run the installer.sh script or download it manually:""$NC"
    echo -e "$RED""      https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh ""$NC"
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  OBJDUMP="$EXT_DIR""/objdump"

  print_output "    objdump - \\c" "no_log"
  if [[ -f "$OBJDUMP" ]] && ( file "$OBJDUMP" | grep -q ELF ) ; then
    echo -e "$GREEN""ok""$NC"
    if [[ -n $ARCH_STR ]] ; then
      if ! "$OBJDUMP" --help | grep -q -e "$ARCH_STR" 2> /dev/null ; then
        #OBJDMP_ARCH="--architecture=""$ARCH_STR"
        #export OBJDMP_ARCH
      #else
        echo -e "$RED""    objdump does not support the used architecture""$NC"
        if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
          exit 1
        fi
      fi
    fi
  else
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing objdump binary""$NC"
    echo -e "$RED""    you can run the installer.sh script or compile it manually""$NC"
  fi

  print_output "    shellcheck - \\c" "no_log"
  if ! command -v shellcheck > /dev/null ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    shellcheck not found ... disabling tests""$NC"
    echo -e "$RED""    install shellcheck via apt-get install shellcheck""$NC"
    SHELLCHECK=0
    export SHELLCHECK
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    tree - \\c" "no_log"
  if ! command -v tree > /dev/null ; then
    echo -e "$ORANGE""not ok""$NC"
    echo -e "$ORANGE""    install tree as alternative to ls for file overview in log""$NC"
    echo -e "$ORANGE""    install tree via apt-get install tree""$NC"
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    vulnerability database - \\c" "no_log"
  if ! [[ -f "$EXT_DIR""/allitems.csv" ]] ; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    missing vulnerability database ...disable tests ""$NC"
    echo -e "$RED""    you can run the installer.sh script or download it manually:""$NC"
    echo -e "$RED""    check https://cve.mitre.org/data/downloads/index.html for the database in CSV format""$NC"
    V_FEED=0
    export V_FEED
    if [[ $ONLY_DEP -eq 0 ]] && [[ $FORCE -eq 0 ]] ; then
      exit 1
    fi
  else
    echo -e "$GREEN""ok""$NC"
  fi

  print_output "    yara - \\c" "no_log"
  YARA_BIN=$(command -v yara)
  # check for needed dependencies:
  if ! [[ -x "$YARA_BIN" ]] ; then
    echo -e "$ORANGE""not ok""$NC"
    echo -e "$ORANGE""    missing yara binary""$NC"
    export YARA=0
  else
    echo -e "$GREEN""ok""$NC"
  fi
  
  if [[ $ONLY_DEP -eq 0 ]] ; then
    if ! [[ -d "$LOG_DIR" ]] ; then
      mkdir "$LOG_DIR" 2> /dev/null
    fi
    if [[ $FIRMWARE -eq 1 ]] ; then
      if ! [[ -d "$LOG_DIR""/vul_func_chcker" ]] ; then
        mkdir -p "$LOG_DIR""/vul_func_checker" 2> /dev/null
      fi
      if ! [[ -d "$LOG_DIR""/objdumps" ]] ; then
        mkdir -p "$LOG_DIR""/objdumps" 2> /dev/null
      fi
      if ! [[ -d "$LOG_DIR""/dtb_dump" ]] && [[ $DTBDUMP -eq 1 ]] ; then
        mkdir -p "$LOG_DIR""/dtb_dump" 2> /dev/null
      fi
      if ! [[ -d "$LOG_DIR""/bap_cwe_checker" ]] && [[ $BAP -eq 1 ]] ; then
        mkdir "$LOG_DIR""/bap_cwe_checker" 2> /dev/null
      fi
    fi
  else
    echo
    print_help
    exit
  fi
}

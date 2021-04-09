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
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs needed stuff for emba

export DEBIAN_FRONTEND=noninteractive

INSTALL_APP_LIST=()
DOWNLOAD_FILE_LIST=()

# force install everything
FORCE=0
# install docker emba
IN_DOCKER=0
# list dependencies
LIST_DEP=0

## Color definition
RED="\033[0;31m"
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
NC="\033[0m"  # no color

## Attribute definition
BOLD="\033[1m"

# print_tool_info a b c
# a = application name (by apt) 
# b = no update, if already installed -> 0
#     update, if already installed -> 1
# c = if given: check if this application is on the system instead of a

print_tool_info(){
  echo -e "\\n""$ORANGE""$BOLD""${1}""$NC"
  TOOL_INFO="$(apt show "${1}" 2> /dev/null)"
  echo -e "$(echo "$TOOL_INFO" | grep "Description:")"
  COMMAND_=""
  if [[ -z "$3" ]] ; then
    COMMAND_="$3"
  else
    COMMAND_="$1"
  fi
  if ( command -v "$COMMAND_" > /dev/null) || ( dpkg -s "${1}" 2> /dev/null | grep -q "Status: install ok installed" ) ; then
    if [[ $2 -eq 0 ]] ; then
      echo -e "$ORANGE""$1"" is already installed and won't be updated.""$NC"
    else
      if [[ $COMPLEMENT -eq 0 ]] ; then
        echo -e "$ORANGE""$1"" will be updated.""$NC"
        INSTALL_APP_LIST+=("$1")
      else
        echo -e "$ORANGE""$1"" won't be updated.""$NC"
      fi
    fi
  else
    echo -e "$ORANGE""$1"" will be newly installed.""$NC"
    INSTALL_APP_LIST+=("$1")
  fi
}

# print_file_info a b c d e
# a = file name
# b = description of file
# c = file url
# d = path on system
# e = if given: check this path or application is on the system instead of d

print_file_info()
{
  echo -e "\\n""$ORANGE""$BOLD""${1}""$NC"
  if [[ -n "${2}" ]] ; then
    echo -e "Description: ""${2}"
  fi
  #echo "$(wget "${3}" --spider --server-response -O -)"
  FILE_SIZE=$(($(wget "${3}" --spider --server-response -O - 2>&1 | sed -ne '/Content-Length/{s/.*: //;p}')))
  if (( FILE_SIZE == 0 )) ; then
    FILE_SIZE=$(($(wget "${3}" --spider --server-response -O - 2>&1 | sed -ne '/content-length/{s/.*: //;p}')))
  fi 
  if (( FILE_SIZE > 1048576 )) ; then
    echo -e "Download-Size: ""$(( FILE_SIZE / 1048576 ))"" MB"
  elif (( FILE_SIZE > 1024 )) ; then
    echo -e "Download-Size: ""$(( FILE_SIZE / 1024 ))"" KB"
  else
    echo -e "Download-Size: ""$FILE_SIZE"" B"
  fi
  if ! [[ -f "${4}" ]] ; then
    if [[ -n "${5}" ]] ; then
      if [[ -f "${5}" ]] || ( command -v "${5}" > /dev/null) || ( dpkg -s "${5}" 2> /dev/null | grep -q "Status: install ok installed" ) ; then
        echo -e "$ORANGE""$1"" won't be downloaded.""$NC"
      else
        echo -e "$ORANGE""$1"" will be downloaded.""$NC"
        DOWNLOAD_FILE_LIST+=("$1")
      fi
    else
      echo -e "$ORANGE""${1}"" will be downloaded.""$NC"
      DOWNLOAD_FILE_LIST+=("${1}")
    fi
  else
    echo -e "$ORANGE""${1}"" is already been downloaded.""$NC"
  fi
}

# download_file a b c
# a = file name
# b = file url
# c = path on system

download_file()
{
  for D_FILE in "${DOWNLOAD_FILE_LIST[@]}" ; do
    if [[ "$D_FILE" == "${1}" ]] ; then
      echo -e "\\n""$ORANGE""$BOLD""Downloading ""${1}""$NC"
      if ! [[ -f "${3}" ]] ; then
        wget "${2}" -O "${3}"
      else
        echo -e "$ORANGE""${1}"" is already downloaded""$NC"
      fi
    fi
  done
  if [[ -f "${3}" ]] && ! [[ -x "${3}" ]] ; then
    chmod +x "${3}"
  fi
}

print_help()
{
  echo -e "\\n""$CYAN""USAGE""$NC"
  echo -e "$CYAN""-F""$NC""         Installation of emba with all dependencies (typical initial installation)"
  echo -e "$CYAN""-c""$NC""         Complements emba dependencies (get/install all missing files/applications)"
  echo -e "$CYAN""-d""$NC""         Force install of all dependencies needed for emba in Docker mode (-D)"
  echo -e "$CYAN""-h""$NC""         Print this help message"
  echo -e "$CYAN""-l""$NC""         List all dependencies of emba"
  echo
}


echo -e "\\n""$ORANGE""$BOLD""Embedded Linux Analyzer Installer""$NC""\\n""$BOLD""=================================================================""$NC"

while getopts cdDFhl OPT ; do
  case $OPT in
    c)
      export COMPLEMENT=1
      export FORCE=1
      echo -e "$GREEN""$BOLD""Complement emba dependecies""$NC"
      ;;
    d)
      export DOCKER_SETUP=1
      export FORCE=1
      echo -e "$GREEN""$BOLD""Install all dependecies for emba in Docker mode (-D)""$NC"
      ;;
    D)
      export IN_DOCKER=1
      echo -e "$GREEN""$BOLD""Install emba on docker""$NC"
      ;;
    F)
      export FORCE=1
      echo -e "$GREEN""$BOLD""Install all dependecies""$NC"
      ;;
    h)
      print_help
      exit 0
      ;;
    l)
      export LIST_DEP=1
      echo -e "$GREEN""$BOLD""List all dependecies (except pip packages)""$NC"
      ;;
    *)
      echo -e "$RED""$BOLD""Invalid option""$NC"
      print_help
      exit 1
      ;;
  esac
done

if ! [[ $EUID -eq 0 ]] && [[ $LIST_DEP -eq 0 ]] ; then
  echo -e "\\n""$RED""Run emba installation script with root permissions!""$NC\\n"
  print_help
  exit 1
fi

# standard stuff before installation run

if [[ $LIST_DEP -eq 0 ]] ; then
  if ! [[ -d "external" ]] ; then
    echo -e "\\n""$ORANGE""Created ./external""$NC"
    mkdir external
  fi

  echo -e "\\n""$ORANGE""Update package lists.""$NC"
  apt-get update
fi

# applications needed for emba to run

echo -e "\\nTo use emba, some applications must be installed and some data (database for CVS for example) downloaded and parsed."
echo -e "\\n""$ORANGE""$BOLD""These applications will be installed/updated:""$NC"
print_tool_info "tree" 1
print_tool_info "yara" 1
print_tool_info "shellcheck" 1
print_tool_info "pylint" 1
print_tool_info "php" 1
print_tool_info "device-tree-compiler" 1
print_tool_info "unzip" 1
print_tool_info "docker-compose" 1
print_tool_info "qemu-user-static" 0 "qemu-mips-static"
print_tool_info "binwalk" 0
print_tool_info "bc" 1
print_tool_info "coreutils" 1
print_tool_info "ent" 1
# needed for sshdcc:
print_tool_info "tcllib" 1
# as we need it for multiple tools we can install it by default
print_tool_info "git" 1

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to install/update these applications?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""These applications will be installed/updated!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    echo
    apt-get install "${INSTALL_APP_LIST[@]}" -y
  ;;
esac

# cwe checker docker

echo -e "\\nWith emba you can automatically find vulnerable pattern in binary executables (just start emba with the parameter -c). Docker and the cwe_checker from fkiecad are required for this."
INSTALL_APP_LIST=()
print_tool_info "docker.io" 0 "docker"

if command -v docker > /dev/null ; then
  echo -e "\\n""$ORANGE""$BOLD""fkiecad/cwe_checker docker image""$NC"
  export DOCKER_CLI_EXPERIMENTAL=enabled
  f="$(docker manifest inspect fkiecad/cwe_checker:latest | grep "size" | sed -e 's/[^0-9 ]//g')"
  echo "Download-Size : ""$(($(( ${f//$'\n'/+} ))/1048576))"" MB"
  export DOCKER_CLI_EXPERIMENTAL=disabled
else
  echo -e "\\n""$ORANGE""$BOLD""fkiecad/cwe_checker docker image""$NC"
  echo "Download-Size: ~600 MB"
fi

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] && [[ $DOCKER_SETUP -eq 0 ]]; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to install Docker (if not already on the system) and download the image?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]]; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""Docker will be installed (if not already on the system) and the image be downloaded!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    apt-get install "${INSTALL_APP_LIST[@]}" -y
    if [[ "$(docker images -q fkiecad/cwe_checker:latest 2> /dev/null)" == "" ]] ; then
      echo -e "$ORANGE""fkiecad/cwe_checker docker image will be downloaded""$NC"
      docker pull fkiecad/cwe_checker:latest
    else
      echo -e "$ORANGE""fkiecad/cwe_checker docker image is already downloaded""$NC"
    fi
  ;;
esac

# FACT-extractor docker

echo -e "\\nWith emba you can automatically use FACT-extractor as a second extraction tool. Docker and the fact_extractor from fkiecad are required for this."
INSTALL_APP_LIST=()
print_tool_info "docker.io" 0 "docker"
print_file_info "FACT-extract" "Extractor for most of the common container formats" "https://raw.githubusercontent.com/fkie-cad/fact_extractor/master/extract.py" "external/extract.py"

if command -v docker > /dev/null ; then
  echo -e "\\n""$ORANGE""$BOLD""fkiecad/fact_extractor docker image""$NC"
  export DOCKER_CLI_EXPERIMENTAL=enabled
  f="$(docker manifest inspect fkiecad/fact_extractor:latest | grep "size" | sed -e 's/[^0-9 ]//g')"
  echo "Download-Size : ""$(($(( ${f//$'\n'/+} ))/1048576))"" MB"
  export DOCKER_CLI_EXPERIMENTAL=disabled
else
  echo -e "\\n""$ORANGE""$BOLD""fkiecad/fact_extractor docker image""$NC"
  echo "Download-Size: ~700 MB"
fi


if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] && [[ $DOCKER_SETUP -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to install Docker (if not already on the system) and download the image?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""Docker will be installed (if not already on the system) and the image be downloaded!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    apt-get install "${INSTALL_APP_LIST[@]}" -y
    if [[ "$(docker images -q fkiecad/fact_extractor:latest 2> /dev/null)" == "" ]] ; then
      echo -e "$ORANGE""fkiecad/fact_extractor docker image will be downloaded""$NC"
      docker pull fkiecad/fact_extractor:latest
    else
      echo -e "$ORANGE""fkiecad/fact_extractor docker image is already downloaded""$NC"
    fi
    download_file "FACT-extract" "https://raw.githubusercontent.com/fkie-cad/fact_extractor/master/extract.py" "external/extract.py"
  ;;
esac


# open source tools from github

echo -e "\\nWe use a few well-known open source tools in emba, for example checksec."

print_file_info "linux-exploit-suggester" "Linux privilege escalation auditing tool" "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "external/linux-exploit-suggester.sh"
print_file_info "checksec" "Check the properties of executables (like PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)" "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" "external/checksec"
print_file_info "sshdcc" "Check SSHd configuration files" "https://raw.githubusercontent.com/sektioneins/sshdcc/master/sshdcc" "external/sshdcc"
print_file_info "sudo-parser.pl" "Parses and tests sudoers configuration files" "https://raw.githubusercontent.com/CiscoCXSecurity/sudo-parser/master/sudo-parser.pl" "external/sudo-parser.pl"

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download these applications (if not already on the system)?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""These applications (if not already on the system) will be downloaded!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    download_file "linux-exploit-suggester" "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "external/linux-exploit-suggester.sh"
    download_file "checksec" "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" "external/checksec"
    download_file "sshdcc" "https://raw.githubusercontent.com/sektioneins/sshdcc/master/sshdcc" "external/sshdcc"
    download_file "sudo-parser.pl" "https://raw.githubusercontent.com/CiscoCXSecurity/sudo-parser/master/sudo-parser.pl" "external/sudo-parser.pl"
  ;;
esac


# yara rules

echo -e "\\nWe are using yara in emba and to improve the experience with emba, you should download some yara rules."

print_file_info "Xumeiquer/yara-forensics/compressed.yar" "" "https://raw.githubusercontent.com/Xumeiquer/yara-forensics/master/file/compressed.yar" "external/yara/compressed.yar"
print_file_info "DiabloHorn/yara4pentesters/juicy_files.txt" "" "https://raw.githubusercontent.com/DiabloHorn/yara4pentesters/master/juicy_files.txt" "external/yara/juicy_files.yar"
print_file_info "ahhh/YARA/crypto_signatures.yar" "" "https://raw.githubusercontent.com/ahhh/YARA/master/crypto_signatures.yar" "external/yara/crypto_signatures.yar"
print_file_info "Yara-Rules/rules/packer_compiler_signatures.yar" "" "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer_compiler_signatures.yar" "external/yara/packer_compiler_signatures.yar"

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download these rules (if not already on the system)?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""These rules (if not already on the system) will be downloaded!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    if ! [[ -d "external/yara/" ]] ; then
      mkdir external/yara
    fi
    download_file "Xumeiquer/yara-forensics/compressed.yar" "https://raw.githubusercontent.com/Xumeiquer/yara-forensics/master/file/compressed.yar" "external/yara/compressed.yar"
    download_file "DiabloHorn/yara4pentesters/juicy_files.txt" "https://raw.githubusercontent.com/DiabloHorn/yara4pentesters/master/juicy_files.txt" "external/yara/juicy_files.yar"
    download_file "ahhh/YARA/crypto_signatures.yar" "https://raw.githubusercontent.com/ahhh/YARA/master/crypto_signatures.yar" "external/yara/crypto_signatures.yar"
    download_file "Yara-Rules/rules/packer_compiler_signatures.yar" "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer_compiler_signatures.yar" "external/yara/packer_compiler_signatures.yar"
  ;;
esac


# binutils - objdump

BINUTIL_VERSION_NAME="binutils-2.35.1"

echo -e "\\nWe are using objdump in emba to get more information from object files. This application is in the binutils package and has to be compiled. We also need following applications for compiling:"
INSTALL_APP_LIST=()

print_file_info "$BINUTIL_VERSION_NAME" "The GNU Binutils are a collection of binary tools." "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz" "external/objdump"
print_tool_info "texinfo" 1
print_tool_info "gcc" 1
print_tool_info "build-essential" 1
print_tool_info "gawk" 1
print_tool_info "bison" 1

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download ""$BINUTIL_VERSION_NAME"" (if not already on the system) and compile objdump?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""$BINUTIL_VERSION_NAME"" will be downloaded (if not already on the system) and objdump compiled!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    apt-get install "${INSTALL_APP_LIST[@]}" -y
    download_file "$BINUTIL_VERSION_NAME" "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz"
    if [[ -f "external/$BINUTIL_VERSION_NAME.tar.gz" ]] ; then
      tar -zxf external/"$BINUTIL_VERSION_NAME".tar.gz -C external
      cd external/"$BINUTIL_VERSION_NAME"/ || exit 1
      echo -e "$ORANGE""$BOLD""Compile objdump""$NC"
      ./configure --enable-targets=all
      make
      cd ../.. || exit 1
    fi
    if [[ -f "external/$BINUTIL_VERSION_NAME/binutils/objdump" ]] ; then
      mv "external/$BINUTIL_VERSION_NAME/binutils/objdump" "external/objdump"
      rm -R "external/""$BINUTIL_VERSION_NAME"
      rm "external/""$BINUTIL_VERSION_NAME"".tar.gz"
      if [[ -f "external/objdump" ]] ; then
        echo -e "$GREEN""objdump installed successfully""$NC"
      fi
    else
      echo -e "$ORANGE""objdump installation failed - check it manually""$NC"
    fi
  ;;
esac


# CSV and CVSS databases

echo -e "\\nTo check binaries to known CSV entries and CVSS values, we need a vulnerability database. Additional we have to parse data and need jq as tool for it, if it's missing, it will be installed."

NVD_URL="https://nvd.nist.gov/feeds/json/cve/1.1/"
INSTALL_APP_LIST=()

print_file_info "cve.mitre.org database" "CVE® is a list of records—each containing an identification number, a description, and at least one public reference—for publicly known cybersecurity vulnerabilities." "https://cve.mitre.org/data/downloads/allitems.csv" "external/allitems.csv"
print_tool_info "jq" 1
for YEAR in $(seq 2002 $(($(date +%Y)))); do
  NVD_FILE="nvdcve-1.1-""$YEAR"".json"
  print_file_info "$NVD_FILE" "" "$NVD_URL""$NVD_FILE"".zip" "external/nvd/""$NVD_FILE"".zip" "./external/allitemscvss.csv"
done

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download these databases and install jq (if not already on the system)?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""These databases will be downloaded and jq be installed (if not already on the system)!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    apt-get install "${INSTALL_APP_LIST[@]}" -y
    download_file "cve.mitre.org database" "https://cve.mitre.org/data/downloads/allitems.csv" "external/allitems.csv"
    if ! [[ -d "external/nvd" ]] ; then
      mkdir external/nvd
    fi
    for YEAR in $(seq 2002 $(($(date +%Y)))); do
      NVD_FILE="nvdcve-1.1-""$YEAR"".json"
      download_file "$NVD_FILE" "$NVD_URL""$NVD_FILE"".zip" "external/nvd/""$NVD_FILE"".zip"

      if [[ -f "external/nvd/""$NVD_FILE"".zip" ]] ; then
        unzip -o "./external/nvd/""$NVD_FILE"".zip" -d "./external/nvd"
        jq -r '. | .CVE_Items[] | [.cve.CVE_data_meta.ID, (.impact.baseMetricV2.cvssV2.baseScore|tostring), (.impact.baseMetricV3.cvssV3.baseScore|tostring)] | @csv' "./external/nvd/""$NVD_FILE" -c | sed -e 's/\"//g' >> "./external/allitemscvss.csv"
        rm "external/nvd/""$NVD_FILE"".zip"
        rm "external/nvd/""$NVD_FILE"
      else
        echo -e "$ORANGE""$NVD_FILE"" is not available or a valid zip archive""$NC"
      fi
    done
    rmdir "external/nvd/"
  ;;
esac

# cve-search database for host 

echo -e "\\nTo use the aggregator and check if exploits are available, we need a searchable exploit database."

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] && [[ $DOCKER_SETUP -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install cve-search and mongodb and populate it?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""cve-search and mongodb will be downloaded, installed and populated!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
    echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
    apt-get update -y
    apt-get install mongodb-org -y
    systemctl daemon-reload
    systemctl start mongod
    systemctl enable mongod
    
    if [[ "$FORCE" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and update the cve-search database?""$NC"
      read -p "(y/N)" -r ANSWER
    else
      echo -e "\\n""$MAGENTA""$BOLD""The cve-search database will be downloaded and updated!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        
        git clone https://github.com/cve-search/cve-search.git external/cve-search
        cd ./external/cve-search/ || exit 1
        pip3 install -r requirements.txt
        xargs sudo apt-get install -y < requirements.system
        /etc/init.d/redis-server start
        ./sbin/db_mgmt_cpe_dictionary.py -p
        ./sbin/db_mgmt_json.py -p
        ./sbin/db_updater.py -c
        cd ../.. || exit 1
        sed -e "s#EMBA_INSTALL_PATH#$(pwd)#" config/cve_database_updater.init > config/cve_database_updater
        chmod +x config/cve_database_updater
        echo -e "\\n""$MAGENTA""$BOLD""The cron.daily update script for the cve-search database is located in config/cve_database_updater""$NC"
        echo -e "$MAGENTA""$BOLD""For automatic updates it should be copied to /etc/cron.daily/""$NC"
        echo -e "$MAGENTA""$BOLD""For manual updates just start it via sudo ./config/cve_database_updater""$NC"
      ;;
    esac
  ;;
esac

# aggregator tools to 

echo -e "\\nTo use the aggregator and check if exploits are available, we need cve-search and cve-searchsploit."
INSTALL_APP_LIST=()
print_tool_info "python3-pip" 1
print_tool_info "net-tools" 1

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install the net-tools, pip3, cve-search and cve_searchsploit (if not already on the system)?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""net-tools, pip3, cve-search and cve_searchsploit (if not already on the system) will be downloaded and be installed!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    apt-get install "${INSTALL_APP_LIST[@]}" -y
    pip3 install cve_searchsploit
    git clone https://github.com/cve-search/cve-search.git external/cve-search
    cd ./external/cve-search/ || exit 1
    pip3 install -r requirements.txt
    xargs sudo apt-get install -y < requirements.system
    cd ../.. || exit 1

    if [[ "$IN_DOCKER" -eq 1 ]] ; then
      if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
        echo -e "\\n""$MAGENTA""$BOLD""Do you want to update the cve_searchsploit database on docker emba?""$NC"
        read -p "(y/N)" -r ANSWER
      else
        echo -e "\\n""$MAGENTA""$BOLD""Updating cve_searchsploit database on docker.""$NC"
        ANSWER=("y")
      fi
      case ${ANSWER:0:1} in
        y|Y )
          cve_searchsploit -u
        ;;
      esac    
    fi
  ;;
esac


# binwalk

INSTALL_APP_LIST=()
print_tool_info "python3-pip" 1
print_tool_info "python3-crypto" 1
print_tool_info "python3-opengl" 1
print_tool_info "python3-pyqt5" 1
print_tool_info "python3-pyqt5.qtopengl" 1
print_tool_info "python3-numpy" 1
print_tool_info "python3-scipy" 1
print_tool_info "mtd-utils" 1
print_tool_info "gzip" 1
print_tool_info "bzip2" 1
print_tool_info "tar" 1
print_tool_info "arj" 1
print_tool_info "lhasa" 1
print_tool_info "p7zip" 1
print_tool_info "p7zip-full" 1
print_tool_info "cabextract" 1
print_tool_info "cramfsswap" 1
print_tool_info "squashfs-tools" 1
print_tool_info "sleuthkit" 1
print_tool_info "default-jdk" 1
print_tool_info "lzop" 1
print_tool_info "srecord" 1
print_tool_info "build-essential" 1
print_tool_info "zlib1g-dev" 1
print_tool_info "liblzma-dev" 1
print_tool_info "liblzo2-dev" 1
# print_tool_info "firmware-mod-kit" 1
# This is no valid packet, couldn't be found

if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install binwalk, yaffshiv, sasquatch, jefferson, unstuff, cramfs-tools and ubi_reader (if not already on the system)?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""binwalk, yaffshiv, sasquatch, jefferson, unstuff, cramfs-tools and ubi_reader (if not already on the system) will be downloaded and be installed!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    if [[ -f "/usr/local/bin/binwalk" ]]; then
      echo -e "Found binwalk. Skipping installation."
    else

      apt-get install "${INSTALL_APP_LIST[@]}" -y

      pip3 install nose
      pip3 install coverage
      pip3 install pyqtgraph
      pip3 install capstone
      pip3 install cstruct

      git clone https://github.com/ReFirmLabs/binwalk.git external/binwalk

      git clone https://github.com/devttys0/yaffshiv external/binwalk/yaffshiv
      sudo python3 ./external/binwalk/yaffshiv/setup.py install

      git clone https://github.com/devttys0/sasquatch external/binwalk/sasquatch
      sudo CFLAGS=-fcommon ./external/binwalk/sasquatch/build.sh -y

      git clone https://github.com/sviehb/jefferson external/binwalk/jefferson
      sudo pip3 install -r ./external/binwalk/jefferson/requirements.txt
      sudo python3 ./external/binwalk/jefferson/setup.py install

      mkdir ./external/binwalk/unstuff
      wget -O ./external/binwalk/unstuff/stuffit520.611linux-i386.tar.gz http://downloads.tuxfamily.org/sdtraces/stuffit520.611linux-i386.tar.gz
      tar -zxv -f ./external/binwalk/unstuff/stuffit520.611linux-i386.tar.gz -C ./external/binwalk/unstuff
      sudo cp ./external/binwalk/unstuff/bin/unstuff /usr/local/bin/
      
      sudo ln -s /opt/firmware-mod-kit/trunk/src/cramfs-2.x/cramfsck /usr/bin/cramfsck

      git clone https://github.com/npitre/cramfs-tools external/binwalk/cramfs-tools
      make -C ./external/binwalk/cramfs-tools/
      install ./external/binwalk/cramfs-tools/mkcramfs /usr/local/bin
      sudo install ./external/binwalk/cramfs-tools/cramfsck /usr/local/bin

      git clone https://github.com/jrspruitt/ubi_reader external/binwalk/ubi_reader
      cd ./external/binwalk/ubi_reader || exit 1
      git reset --hard 0955e6b95f07d849a182125919a1f2b6790d5b51
      sudo python2 setup.py install
      cd .. || exit 1

      sudo python3 setup.py install
      cd ../.. || exit 1

      rm -rf ./external/binwalk

      if [[ -f "/usr/local/bin/binwalk" ]] ; then
        echo -e "$GREEN""binwalk installed successfully""$NC"
      else
        echo -e "$ORANGE""binwalk installation failed - check it manually""$NC"
      fi
    fi
  ;;
esac


# aha for html generation
INSTALL_APP_LIST=()
echo -e "\\nTo use the emba report generator, we need a html file generator. make will be needed to compile aha."
print_tool_info "make" 0
if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and compile aha (if not already on the system)?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
  ANSWER=("n")
else
  echo -e "\\n""$MAGENTA""$BOLD""aha (if not already on the system) will be downloaded and be compiled!""$NC"
  ANSWER=("y")
fi
case ${ANSWER:0:1} in
  y|Y )
    if ! [[ -f "external/aha" ]] ; then
      apt-get install "${INSTALL_APP_LIST[@]}" -y
      wget https://github.com/theZiz/aha/archive/master.zip -O external/aha-master.zip
      unzip ./external/aha-master.zip -d ./external
      rm external/aha-master.zip
      cd ./external/aha-master || exit 1
      echo -e "$ORANGE""$BOLD""Compile aha""$NC"
      make
      cd ../.. || exit 1
      mv "external/aha-master/aha" "external/aha"
      rm -R external/aha-master
      
      if ! [[ -f "external/aha" ]] ; then
         echo -e "$MAGENTA""$BOLD""aha installation failed! You can not use the emba report manager""$NC"
      else
         echo -e "$GREEN""aha has been installed""$NC"
      fi
    else
      echo -e "$ORANGE""aha is already installed""$NC"
    fi      
  ;;
esac

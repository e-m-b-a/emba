#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  installs needed stuff:
#                 Yara rules
#                 checksec
#                 linux-exploit-suggester.sh

INSTALL_APP_LIST=()
DOWNLOAD_FILE_LIST=()

# print_tool_info a b c
# a = application name (by apt) 
# b = no update, if already installed -> 0
#     update, if already installed -> 1
# c = if given: check if this application is on the system instead of a

print_tool_info(){
  echo -e "\\n""$ORANGE""$BOLD""${1}""$NC"
  TOOL_INFO="$(apt show "${1}" 2> /dev/null)"
  echo -e "$(echo "$TOOL_INFO" | grep "Description:")"
  echo -e "$(echo "$TOOL_INFO" | grep "Download-Size:")"" | ""$(echo "$TOOL_INFO" | grep "Installed-Size:")"
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
      echo -e "$ORANGE""$1"" will be updated.""$NC"
      INSTALL_APP_LIST+=("$1")
    fi
  else
    echo -e "$ORANGE""$1"" will be newly installed.""$NC"
    INSTALL_APP_LIST+=("$1")
  fi
}

# print_file_info a b c
# a = file name
# b = description of file
# c = file url
# d = path on system

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
    echo -e "$ORANGE""${1}"" will be downloaded.""$NC"
    DOWNLOAD_FILE_LIST+=("${1}")
  else
    echo -e "$ORANGE""${1}"" is already downloaded.""$NC"
  fi
}

# download_file a b c
# a = file name
# b = file url
# c = path on system

download_file()
{
  for D_FILE in "${DOWNLOAD_FILE_LIST[@]}" ; do
    echo "$D_FILE"
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


ORANGE='\033[0;33m'
BOLD='\033[1m'
MAGENTA='\033[0;35m'
NC='\033[0m'  # no color

echo -e "\\n""$ORANGE""$BOLD""Embedded Linux Analyzer Installer""$NC""\\n""$BOLD""=================================================================""$NC"

if ! [[ $EUID -eq 0 ]] ; then
  echo -e "\\n""$ORANGE""Run emba installation script with root permissions!""$NC\\n"
  exit 1
fi



# applications needed for emba to run

echo -e "\\nTo use emba, some applications must be installed and some data (database for CVS for example) downloaded and parsed."
echo -e "\\n""$ORANGE""$BOLD""These applications will be installed/updated:""$NC"
print_tool_info "tree" 1
print_tool_info "yara" 1
print_tool_info "shellcheck" 1
print_tool_info "device-tree-compiler" 1
print_tool_info "unzip" 1
print_tool_info "qemu-user-static" 0 "qemu-mips-static"
print_tool_info "binwalk" 0

echo -e "\\n""$MAGENTA""$BOLD""Do you want to install/update these applications?""$NC"
read -p "(y/N)" -r ANSWER
case ${ANSWER:0:1} in
  y|Y )
    echo
    for APP in "${INSTALL_APP_LIST[@]}" ; do
      apt-get install "$APP" -y
    done
  ;;
esac

if ! [[ -d "external" ]] ; then
  mkdir external
fi



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
  echo "Download-Size: ~1500 MB"
fi
if [[ "$(docker images -q fkiecad/cwe_checker:latest 2> /dev/null)" == "" ]] ; then
  echo -e "$ORANGE""fkiecad/cwe_checker docker image will be downloaded""$NC"
else
  echo -e "$ORANGE""fkiecad/cwe_checker docker image is already downloaded""$NC"
fi

echo -e "\\n""$MAGENTA""$BOLD""Do you want to install Docker (if not already on the system) and download the image?""$NC"
read -p "(y/N)" -r ANSWER
case ${ANSWER:0:1} in
  y|Y )
    for APP in "${INSTALL_APP_LIST[@]}" ; do
      apt-get install "$APP" -y
    done
    if [[ "$(docker images -q fkiecad/cwe_checker:latest 2> /dev/null)" == "" ]] ; then
      docker pull fkiecad/cwe_checker:latest
    fi
  ;;
esac

# open source tools from github

echo -e "\\nWe use a few well-known open source tools in emba, for example checksec."

print_file_info "linux-exploit-suggester" "Linux privilege escalation auditing tool" "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "external/linux-exploit-suggester.sh"
print_file_info "checksec" "Check the properties of executables (like PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)" "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" "external/checksec"

echo -e "\\n""$MAGENTA""$BOLD""Do you want to download these applications (if not already on the system)?""$NC"
read -p "(y/N)" -r ANSWER
case ${ANSWER:0:1} in
  y|Y )
    download_file "linux-exploit-suggester" "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "external/linux-exploit-suggester.sh"
    download_file "checksec" "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" "external/checksec"
  ;;
esac


# yara rules

echo -e "\\nWe are using yara in emba and to improve the experience with emba, you should download some yara rules."

print_file_info "Xumeiquer/yara-forensics/compressed.yar" "" "https://raw.githubusercontent.com/Xumeiquer/yara-forensics/master/file/compressed.yar" "external/yara/compressed.yar"
print_file_info "DiabloHorn/yara4pentesters/juicy_files.txt" "" "https://raw.githubusercontent.com/DiabloHorn/yara4pentesters/master/juicy_files.txt" "external/yara/juicy_files.yar"
print_file_info "ahhh/YARA/crypto_signatures.yar" "" "https://raw.githubusercontent.com/ahhh/YARA/master/crypto_signatures.yar" "external/yara/crypto_signatures.yar"
print_file_info "Yara-Rules/rules/packer_compiler_signatures.yar" "" "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer_compiler_signatures.yar" "external/yara/packer_compiler_signatures.yar"

echo -e "\\n""$MAGENTA""$BOLD""Do you want to download these rules (if not already on the system)?""$NC"
read -p "(y/N)" -r ANSWER
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

print_file_info "$BINUTIL_VERSION_NAME" "The GNU Binutils are a collection of binary tools." "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz"

print_tool_info "texinfo" 1
print_tool_info "gcc" 1
print_tool_info "build-essential" 1

echo -e "\\n""$MAGENTA""$BOLD""Do you want to download ""$BINUTIL_VERSION_NAME"" (if not already on the system) and compile objdump?""$NC"
read -p "(y/N)" -r ANSWER
case ${ANSWER:0:1} in
  y|Y )
    for APP in "${INSTALL_APP_LIST[@]}" ; do
      apt-get install "$APP" -y
    done
    download_file "$BINUTIL_VERSION_NAME" "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz"
    tar -zxf external/"$BINUTIL_VERSION_NAME".tar.gz -C external
    cd external/"$BINUTIL_VERSION_NAME"/ || exit 1
    echo -e "$ORANGE""$BOLD""Compile objdump""$NC"
    ./configure --enable-targets=all
    make
    cd ../.. || exit 1
    if [[ -f "external/$BINUTIL_VERSION_NAME/binutils/objdump" ]] ; then
      mv "external/$BINUTIL_VERSION_NAME/binutils/objdump" "external/objdump"
      rm -R external/"$BINUTIL_VERSION_NAME"
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
  print_file_info "$NVD_FILE" "" "$NVD_URL""$NVD_FILE"".zip" "external/nvd/""$NVD_FILE"".zip"
done

echo -e "\\n""$MAGENTA""$BOLD""Do you want to download these databases and install jq (if not already on the system)?""$NC"
read -p "(y/N)" -r ANSWER
case ${ANSWER:0:1} in
  y|Y )
    download_file "cve.mitre.org database" "https://cve.mitre.org/data/downloads/allitems.csv" "external/allitems.csv"
    if ! [[ -d "external/nvd" ]] ; then
      mkdir external/nvd
    fi
    for APP in "${INSTALL_APP_LIST[@]}" ; do
      apt-get install "$APP" -y
    done
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

# aggregator

INSTALL_APP_LIST=()
echo -e "\\nTo use the aggregator and check if exploits are available, we need a searchable exploit database. CVE-searchsploit will be installed via pip3."
print_tool_info "python3-pip" 1
print_tool_info "bc" 1

echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install bc, pip3, cve-search and cve_searchsploit (if not already on the system)?""$NC"
read -p "(y/N)" -r ANSWER
case ${ANSWER:0:1} in
  y|Y )
    for APP in "${INSTALL_APP_LIST[@]}" ; do
      apt-get install "$APP" -y
    done
    pip3 install cve_searchsploit
    if [[ -d external/cve-search ]]; then
      echo -e "Found cve-search directory. Skipping installation."
    else
      git clone https://github.com/cve-search/cve-search.git external/cve-search
    fi
    echo -e "\\n""$MAGENTA""$BOLD""For using CVE-search you have to install all the requirements and the needed database.""$NC"
    echo -e "$MAGENTA""$BOLD""Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation""$NC"
  ;;
esac

# aha for html generation - future extension of emba

INSTALL_APP_LIST=()
echo -e "\\nTo use the aggregator and check if exploits are available, we need a searchable exploit database. CVE-searchsploit will be installed via pip3."
print_tool_info "python3-pip" 1
print_tool_info "bc" 1

echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install bc, pip3, cve-search and cve_searchsploit (if not already on the system)?""$NC"
read -p "(y/N)" -r ANSWER
case ${ANSWER:0:1} in
  y|Y )
    echo -e "\\n""$ORANGE""$BOLD""Downloading aha""$NC"
    if ! [[ -f "external/aha" ]] ; then
       apt-get install make
      mkdir html-files
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
      echo -e "$ORANGE""aha is already downloaded and compiled""$NC"
   fi
  ;;
esac


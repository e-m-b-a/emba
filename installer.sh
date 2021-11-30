#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs needed stuff for EMBA

export DEBIAN_FRONTEND=noninteractive

INSTALL_APP_LIST=()
DOWNLOAD_FILE_LIST=()

# force install everything
FORCE=0
# install docker EMBA
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
  SIZE=$(apt show "$1" 2>/dev/null | grep Download-Size | cut -d: -f2)
  if [[ -n "$SIZE" ]]; then
    echo -e "Download-Size:$SIZE"
  fi
  if echo "$TOOL_INFO" | grep -E "^E:\ "; then
    echo -e "$RED""$1"" was not identified and is not installable.""$NC"
  else
    COMMAND_=""
    if [[ -z "$3" ]] ; then
      COMMAND_="$3"
    else
      COMMAND_="$1"
    fi
    if ( command -v "$COMMAND_" > /dev/null) || ( dpkg -s "${1}" 2> /dev/null | grep -q "Status: install ok installed" ) ; then
      UPDATE=$(apt-cache policy "$1" | grep -i install | cut -d: -f2 | tr -d "^[:blank:]" | uniq | wc -l)
      if [[ "$UPDATE" -eq 1 ]] ; then
        echo -e "$GREEN""$1"" won't be updated.""$NC"
      else
        echo -e "$ORANGE""$1"" will be updated.""$NC"
        INSTALL_APP_LIST+=("$1")
      fi
    else
      echo -e "$ORANGE""$1"" will be newly installed.""$NC"
      INSTALL_APP_LIST+=("$1")
    fi
  fi
}

# print_git_info a b c
# a = tool name
# b = GIT url
# c = description of tool

print_git_info() {
  GIT_NAME="$1"
  GIT_URL="$2"
  GIT_DESC="$3"
  echo -e "\\n""$ORANGE""$BOLD""$GIT_NAME""$NC"
  if [[ -n "$GIT_DESC" ]] ; then
    echo -e "Description: ""$GIT_DESC"
  fi

  GIT_SIZE=$(curl https://api.github.com/repos/"$GIT_URL" 2> /dev/null | jq -r '.size')

  if (( GIT_SIZE > 1024 )) ; then
    echo -e "Download-Size: ""$(( GIT_SIZE / 1024 ))"" MB"
  else
    echo -e "Download-Size: ""$GIT_SIZE"" KB"
  fi
}

# print_pip_info a b
# a = file name
# b = package version

print_pip_info() {
  PIP_NAME="$1"
  if [[ -n "${2}" ]] ; then
    PACKAGE_VERSION="$2"
  fi
  echo -e "\\n""$ORANGE""$BOLD""$PIP_NAME""$NC"
  mapfile -t PIP_INFOS < <(pip3 show "$PIP_NAME" 2>/dev/null)
  # in the error message of pip install we can find all available versions
  PVERSION=$(pip3 install "$PIP_NAME==" 2>&1 | grep -o "$PACKAGE_VERSION")
  for INFO in "${PIP_INFOS[@]}"; do
    if [[ "$INFO" == *"Summary"* ]]; then
      INFO=${INFO//Summary/Description}
      if [[ -n "$PVERSION" ]]; then
        echo -e "$INFO / Version: $PVERSION"
      elif [[ -n "$VERSION" ]]; then
        echo -e "$INFO $VERSION"
      else
        echo -e "$INFO"
      fi
    fi
    if [[ "$INFO" == *"Version"* ]]; then
      VERSION=" / ""$INFO"
    fi
  done

  # we need grep -c -> with -q we got errors
  INSTALLED=$(pip3 list 2>/dev/null | grep -E -c "^${PIP_NAME}[[:space:]]+$PACKAGE_VERSION")
  if [[ "$INSTALLED" -gt 0 ]]; then
    echo -e "$GREEN""$PIP_NAME"" is already installed - no further action performed.""$NC"
  else
    INSTALLED=$(pip3 list 2>/dev/null | grep -E -c "^$PIP_NAME")
    if [[ "$INSTALLED" -gt 0 ]]; then
      echo -e "$ORANGE""$PIP_NAME"" is already installed and will be updated (if a newer version is available).""$NC"
    else
      echo -e "$ORANGE""$PIP_NAME"" will be installed.""$NC"
    fi
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
  # echo "$(wget "${3}" --spider --server-response -O -)"
  FILE_SIZE=$(($(wget "${3}" --spider --server-response 2>&1 | sed -ne '/.ontent-.ength/{s/.*: //;p}' | sed '$!d')))

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
        echo -e "$GREEN""$1"" is already installed - no further action performed.""$NC"
      else
        echo -e "$ORANGE""$1"" will be downloaded.""$NC"
        DOWNLOAD_FILE_LIST+=("$1")
      fi
    else
      echo -e "$ORANGE""${1}"" will be downloaded.""$NC"
      DOWNLOAD_FILE_LIST+=("${1}")
    fi
  else
    echo -e "$ORANGE""${1}"" has already been downloaded.""$NC"
  fi
}

# download_file a b c
# a = file name
# b = file url
# c = path on system
# WARNING: you need to do a print_file_info first!

download_file()
{
  for D_FILE in "${DOWNLOAD_FILE_LIST[@]}" ; do
    if [[ "$D_FILE" == "${1}" ]] ; then
      echo -e "\\n""$ORANGE""$BOLD""Downloading ""${1}""$NC"
      if ! [[ -f "${3}" ]] ; then
        wget "${2}" -O "${3}"
      else
        echo -e "$GREEN""${1}"" is already downloaded - no further action performed.""$NC"
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
  echo -e "$CYAN""-d""$NC""         Default installation of all dependencies needed for EMBA in default/docker mode (typical initial installation)"
  echo -e "$CYAN""-F""$NC""         Installation of EMBA with all dependencies (for running on your host - developer mode)"
#  echo -e "$CYAN""-c""$NC""         Complements EMBA dependencies (get/install all missing files/applications)"
  echo -e "$CYAN""-D""$NC""         Only used via docker-compose for building EMBA docker container"
  echo -e "$CYAN""-C""$NC""         Installs only CVE-search incl. database on the host (used for EMBArk installations)"
  echo -e "$CYAN""-h""$NC""         Print this help message"
  echo -e "$CYAN""-l""$NC""         List all dependencies of EMBA"
  echo
}


echo -e "\\n""$ORANGE""$BOLD""Embedded Linux Analyzer Installer""$NC""\\n""$BOLD""=================================================================""$NC"

if [ "$#" -ne 1 ]; then
  echo -e "$RED""$BOLD""Invalid number of arguments""$NC"
  echo -e "\n\n------------------------------------------------------------------"
  echo -e "Probably you would check all packets we are going to install with:"
  echo -e "$CYAN""     sudo ./installer.sh -l""$NC"
  echo -e "If you are going to install EMBA in default mode you can use:"
  echo -e "$CYAN""     sudo ./installer.sh -d""$NC"
  echo -e "------------------------------------------------------------------\n\n"
  print_help
  exit 1
fi

while getopts cCdDFhl OPT ; do
  case $OPT in
    c)
      export COMPLEMENT=1
      export FORCE=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Complement EMBA dependecies""$NC"
      ;;
    d)
      export DOCKER_SETUP=1
      export FORCE=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install all dependecies for EMBA in default/docker mode""$NC"
      ;;
    C)
      export DOCKER_SETUP=0
      export IN_DOCKER=0
      export FULL=0
      export FORCE=1
      export CVE_SEARCH=1
      echo -e "$GREEN""$BOLD""Install CVE-search including the needed database - used for EMBArk installations""$NC"
      ;;
    D)
      export IN_DOCKER=1
      export DOCKER_SETUP=0
      export FORCE=1
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install EMBA in docker image - used for building a docker image""$NC"
      ;;
    F)
      export FORCE=1
      export FULL=1
      export DOCKER_SETUP=0
      export CVE_SEARCH=0
      echo -e "$GREEN""$BOLD""Install all dependecies for developer mode""$NC"
      ;;
    h)
      print_help
      exit 0
      ;;
    l)
      export LIST_DEP=1
      echo -e "$GREEN""$BOLD""List all dependecies""$NC"
      ;;
    *)
      echo -e "$RED""$BOLD""Invalid option""$NC"
      print_help
      exit 1
      ;;
  esac
done

if ! [[ $EUID -eq 0 ]] && [[ $LIST_DEP -eq 0 ]] ; then
  echo -e "\\n""$RED""Run EMBA installation script with root permissions!""$NC\\n"
  print_help
  exit 1
fi

# standard stuff before installation run

HOME_PATH=$(pwd)

if [[ $LIST_DEP -eq 0 ]] ; then
  if ! [[ -d "external" ]] ; then
    echo -e "\\n""$ORANGE""Created external directory: ./external""$NC"
    mkdir external
  fi

  echo -e "\\n""$ORANGE""Update package lists.""$NC"
  apt-get -y update
fi

# applications needed for EMBA to run

echo -e "\\nTo use EMBA, some applications must be installed and some data (database for CVS for example) downloaded and parsed."
echo -e "\\n""$ORANGE""$BOLD""These applications will be installed/updated:""$NC"
print_tool_info "jq" 1
print_tool_info "shellcheck" 1
print_tool_info "unzip" 1
print_tool_info "docker-compose" 1
print_tool_info "bc" 1
print_tool_info "coreutils" 1
print_tool_info "ncurses-bin" 1
# as we need it for multiple tools we can install it by default
print_tool_info "git" 1
print_tool_info "net-tools" 1

if [[ "$FORCE" -eq 0 ]] && { [[ "$LIST_DEP" -eq 0 ]] || [[ $DOCKER_SETUP -eq 1 ]];}; then
  echo -e "\\n""$MAGENTA""$BOLD""Do you want to install/update these applications?""$NC"
  read -p "(y/N)" -r ANSWER
elif [[ "$LIST_DEP" -eq 1 ]] ; then
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

INSTALL_APP_LIST=()

if [[ "$CVE_SEARCH" -ne 1 ]]; then
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    print_tool_info "make" 1
    print_tool_info "tree" 1
    print_tool_info "yara" 1
    print_tool_info "device-tree-compiler" 1
    print_tool_info "qemu-user-static" 0 "qemu-mips-static"
    print_tool_info "binwalk" 1
    print_tool_info "pylint" 1
    # libguestfs-tools is needed to mount vmdk images
    print_tool_info "libguestfs-tools" 1
    print_tool_info "php" 1
    print_tool_info "ent" 1
    # needed for sshdcc:
    print_tool_info "tcllib" 1
    print_tool_info "radare2" 1
    print_tool_info "metasploit-framework" 1
    print_tool_info "u-boot-tools" 1
    print_tool_info "python3-bandit" 1
    print_tool_info "iputils-ping" 1
  
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
  fi
  
  # download EMBA docker image (only for -d Docker installation)
  
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 0 ]] || [[ $DOCKER_SETUP -eq 1 ]] || [[ $FULL -eq 1 ]]; then
    INSTALL_APP_LIST=()
    print_tool_info "docker.io" 0 "docker"
  
    echo -e "\\n""$ORANGE""$BOLD""embeddedanalyzer/emba docker image""$NC"
    echo -e "Description: EMBA docker images used for firmware analysis."
    if command -v docker > /dev/null ; then
      export DOCKER_CLI_EXPERIMENTAL=enabled
      f="$(docker manifest inspect embeddedanalyzer/emba:latest | grep "size" | sed -e 's/[^0-9 ]//g')"
      echo "Download-Size : ""$(($(( ${f//$'\n'/+} ))/1048576))"" MB"
      if [[ "$(docker images -q embeddedanalyzer/emba 2> /dev/null)" == "" ]]; then
        echo -e "$ORANGE""EMBA docker image will be downloaded.""$NC"
        docker pull embeddedanalyzer/emba
        export DOCKER_CLI_EXPERIMENTAL=disabled
      else
        echo -e "$GREEN""EMBA docker image is already available - no further action will be performed.""$NC"
      fi
      docker-compose up --no-start
    else
      echo "Estimated download-Size: ~2500 MB"
      echo -e "$ORANGE""WARNING: docker command missing - no docker pull possible.""$NC"
    fi
  fi
  
  INSTALL_APP_LIST=()
  
  # cwe-checker
  
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    print_git_info "cwe-checker" "fkie-cad/cwe_checker" "cwe_checker is a suite of checks to detect common bug classes such as use of dangerous functions and simple integer overflows."
    echo -e "$ORANGE""cwe-checker will be downloaded.""$NC"
    print_file_info "OpenJDK" "OpenJDK for cwe-checker" "https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.12%2B7/OpenJDK11U-jdk_x64_linux_hotspot_11.0.12_7.tar.gz" "external/jdk.tar.gz"
    print_file_info "GHIDRA" "Ghidra for cwe-checker" "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.2_build/ghidra_10.0.2_PUBLIC_20210804.zip" "external/ghidra.zip"
  
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
  
        if ! [[ -d ./external/cwe_checker ]]; then
          # cleanup first
          rm "$HOME"/.cargo -r -f
          rm "$HOME"/.config -r -f
          rm external/rustup -r -f
  
          curl https://sh.rustup.rs -sSf | sudo RUSTUP_HOME=external/rustup sh -s -- -y
          # shellcheck disable=SC1090
          # shellcheck disable=SC1091
          source "$HOME/.cargo/env"
          RUSTUP_HOME=external/rustup rustup default stable
          export RUSTUP_TOOLCHAIN=stable 
    
          # Java SDK for ghidra
          if [[ -d ./external/jdk ]] ; then rm -R ./external/jdk ; fi
          curl -L https://github.com/adoptium/temurin11-binaries/releases/download/jdk-11.0.12%2B7/OpenJDK11U-jdk_x64_linux_hotspot_11.0.12_7.tar.gz -Sf -o external/jdk.tar.gz
          mkdir external/jdk 2>/dev/null
          tar -xzf external/jdk.tar.gz -C external/jdk --strip-components 1
          rm external/jdk.tar.gz
    
          # Ghidra
          if [[ -d ./external/ghidra ]] ; then rm -R ./external/ghidra ; fi
          curl -L https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.0.2_build/ghidra_10.0.2_PUBLIC_20210804.zip -Sf -o external/ghidra.zip
          mkdir external/ghidra 2>/dev/null
          unzip -qo external/ghidra.zip -d external/ghidra
          sed -i s@JAVA_HOME_OVERRIDE=@JAVA_HOME_OVERRIDE=external/jdk@g external/ghidra/ghidra_10.0.2_PUBLIC/support/launch.properties
          rm external/ghidra.zip
    
          if [[ -d ./external/cwe_checker ]] ; then rm -R ./external/cwe_checker ; fi
          mkdir external/cwe_checker 2>/dev/null
          git clone https://github.com/fkie-cad/cwe_checker.git external/cwe_checker
          cd external/cwe_checker || exit 1
          make all GHIDRA_PATH=external/ghidra/ghidra_10.0.2_PUBLIC
          cd "$HOME_PATH" || exit 1
  
          mv "$HOME""/.cargo/bin" "external/cwe_checker/bin"
          rm -r -f "$HOME""/.cargo/"
          rm -r ./external/rustup
        else
          echo -e "\\n""$GREEN""cwe-checker already installed - no further action performed.""$NC"
        fi
      ;;
    esac
  fi
  
  # FACT-extractor
  
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    print_git_info "fact-extractor" "m-1-k-3/fact_extractor" "Wraps FACT unpack plugins into standalone utility. Should be able to extract most of the common container formats. (EMBA fork)"
    echo -e "$ORANGE""fact_extractor will be downloaded.""$NC"
  
    if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install FACT-extractor?""$NC"
      read -p "(y/N)" -r ANSWER
    elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]]; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""FACT-extractor will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        if ! [[ -d ./external/fact_extractor ]]; then
          # this is a temporary solution until the official fact repo supports a current kali linux
          git clone https://github.com/m-1-k-3/fact_extractor.git external/fact_extractor
          cd ./external/fact_extractor/fact_extractor/ || exit 1
          ./install/pre_install.sh
          python3 ./install.py
          cd "$HOME_PATH" || exit 1
        fi
    
        if python3 ./external/fact_extractor/fact_extractor/fact_extract.py -h | grep -q "FACT extractor - Standalone extraction utility"; then
          echo -e "$GREEN""FACT-extractor installed""$NC"
        fi
      ;;
    esac
  fi
  
  # open source tools from github
  
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    
    print_file_info "linux-exploit-suggester" "Linux privilege escalation auditing tool" "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "external/linux-exploit-suggester.sh"
    print_file_info "checksec" "Check the properties of executables (like PIE, RELRO, PaX, Canaries, ASLR, Fortify Source)" "https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec" "external/checksec"
    print_file_info "sshdcc" "Check SSHd configuration files" "https://raw.githubusercontent.com/sektioneins/sshdcc/master/sshdcc" "external/sshdcc"
    print_file_info "sudo-parser.pl" "Parses and tests sudoers configuration files" "https://raw.githubusercontent.com/CiscoCXSecurity/sudo-parser/master/sudo-parser.pl" "external/sudo-parser.pl"
    print_file_info "pixd" "pixd is a tool for visualizing binary data using a colour palette." "https://github.com/FireyFly/pixd/pixd.c" "external/pixd"
    print_file_info "progpilot" "progpilot is a tool for static security tests on php files." "https://github.com/designsecurity/progpilot/releases/download/v0.8.0/progpilot_v0.8.0.phar" "external/progpilot"
  
    print_pip_info "pillow"
    
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
        download_file "progpilot" "https://github.com/designsecurity/progpilot/releases/download/v0.8.0/progpilot_v0.8.0.phar" "external/progpilot"
        # pixd installation
        pip3 install pillow 2>/dev/null
        echo -e "\\n""$ORANGE""$BOLD""Downloading of pixd""$NC"
        git clone https://github.com/p4cx/pixd_image external/pixd
        cd ./external/pixd/ || exit 1
        make
        mv pixd ../pixde
        mv pixd_png.py ../pixd_png.py
        cd "$HOME_PATH" || exit 1
        rm -r ./external/pixd/
        # pixd installation
      ;;
    esac
  fi
  
  # yara rules
  
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    
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
  fi
  
  # binutils - objdump
  
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    BINUTIL_VERSION_NAME="binutils-2.35.1"
    
    INSTALL_APP_LIST=()
    
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] ; then
      print_file_info "$BINUTIL_VERSION_NAME" "The GNU Binutils are a collection of binary tools." "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz" "external/objdump"
      print_tool_info "texinfo" 1
      print_tool_info "gcc" 1
      print_tool_info "build-essential" 1
      print_tool_info "gawk" 1
      print_tool_info "bison" 1
      print_tool_info "debuginfod" 1
    fi
    
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
        if ! [[ -f "external/objdump" ]] ; then
          download_file "$BINUTIL_VERSION_NAME" "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz"
          if [[ -f "external/$BINUTIL_VERSION_NAME.tar.gz" ]] ; then
            tar -zxf external/"$BINUTIL_VERSION_NAME".tar.gz -C external
            cd external/"$BINUTIL_VERSION_NAME"/ || exit 1
            echo -e "$ORANGE""$BOLD""Compile objdump""$NC"
            ./configure --enable-targets=all
            make
            cd "$HOME_PATH" || exit 1
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
        else
          echo -e "$GREEN""objdump already installed - no further action performed.""$NC"
        fi
      ;;
    esac
  fi
  
  
  # CSV and CVSS databases
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
  
    NVD_URL="https://nvd.nist.gov/feeds/json/cve/1.1/"
    INSTALL_APP_LIST=()
    
    print_file_info "cve.mitre.org database" "CVE® is a list of publicly known cybersecurity vulnerabilities." "https://cve.mitre.org/data/downloads/allitems.csv" "external/allitems.csv"
    for YEAR in $(seq 2002 $(($(date +%Y)))); do
      NVD_FILE="nvdcve-1.1-""$YEAR"".json"
      print_file_info "$NVD_FILE" "" "$NVD_URL""$NVD_FILE"".zip" "external/nvd/""$NVD_FILE"".zip" "./external/allitemscvss.csv"
    done
    
    if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download these databases?""$NC"
      read -p "(y/N)" -r ANSWER
    elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""These databases will be downloaded and installed (if not already on the system)!""$NC"
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
  fi
  
  # aggregator tools to 
  
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
  
    INSTALL_APP_LIST=()
    print_tool_info "python3-pip" 1
    print_tool_info "net-tools" 1
    print_pip_info "cve-searchsploit"
    
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
        pip3 install cve_searchsploit 2>/dev/null
    
        if [[ "$IN_DOCKER" -eq 1 ]] ; then
          if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
            echo -e "\\n""$MAGENTA""$BOLD""Do you want to update the cve_searchsploit database in EMBA docker environment?""$NC"
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
  fi
  
  #iniscan
  
  INSTALL_APP_LIST=()
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
  
    cd "$HOME_PATH" || exit 1
  
    echo -e "\\nTo check the php.ini config for common security practices we have to install Composer and inicheck."
  
    print_tool_info "php" 1
    print_file_info "iniscan/composer.phar" "A Dependency Manager for PHP" "https://getcomposer.org/installer" "external/iniscan/composer.phar"
  
    if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download Composer and iniscan (if not already on the system)?""$NC"
      read -p "(y/N)" -r ANSWER
    elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""Composer and iniscan (if not already on the system) will be downloaded!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y
        if ! [[ -d "external/iniscan" ]] ; then
          mkdir external/iniscan
        fi
        download_file "iniscan/composer.phar" "https://getcomposer.org/installer" "external/iniscan/composer.phar"
        cd ./external/iniscan || exit 1
        php composer.phar build --no-interaction
        php composer.phar global require psecio/iniscan --no-interaction
        cd "$HOME_PATH" || exit 1
        cp -r "/root/.config/composer/vendor/." "./external/iniscan/"
      ;;
    esac
  fi
  
  # binwalk
  
  INSTALL_APP_LIST=()
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || exit 1
    print_tool_info "python3-pip" 1
    print_tool_info "python3-opengl" 1
    print_tool_info "python3-pyqt5" 1
    print_tool_info "python3-pyqt5.qtopengl" 1
    print_tool_info "python3-numpy" 1
    print_tool_info "python3-scipy" 1
    # python2 is needed for ubireader installation
    print_tool_info "python2" 1
    # python-setuptools is needed for ubireader installation
    print_tool_info "python-setuptools" 1
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
    # firmware-mod-kit is only available on Kali Linux
    print_tool_info "firmware-mod-kit" 1
  
    print_pip_info "nose"
    print_pip_info "coverage"
    print_pip_info "pyqtgraph"
    print_pip_info "capstone"
    print_pip_info "cstruct"
  
    print_git_info "binwalk" "ReFirmLabs/binwalk" "Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images."
    echo -e "$ORANGE""cve-search will be downloaded.""$NC"
    print_git_info "yaffshiv" "devttys0/yaffshiv" "A simple YAFFS file system parser and extractor, written in Python."
    echo -e "$ORANGE""binwalk will be downloaded.""$NC"
    print_git_info "sasquatch" "devttys0/sasquatch" "The sasquatch project is a set of patches to the standard unsquashfs utility (part of squashfs-tools) that attempts to add support for as many hacked-up vendor-specific SquashFS implementations as possible."
    echo -e "$ORANGE""sasquatch will be downloaded.""$NC"
    print_git_info "jefferson" "sviehb/jefferson" "JFFS2 filesystem extraction tool"
    echo -e "$ORANGE""jefferson will be downloaded.""$NC"
    print_git_info "cramfs-tools" "npitre/cramfs-tools" "Cramfs - cram a filesystem onto a small ROM"
    echo -e "$ORANGE""cramfs-tools will be downloaded.""$NC"
    print_git_info "ubi_reader" "jrspruitt/ubi_reader" "UBI Reader is a Python module and collection of scripts capable of extracting the contents of UBI and UBIFS images"
    echo -e "$ORANGE""ubi_reader will be downloaded.""$NC"
    print_file_info "stuffit520.611linux-i386.tar.gz" "Extract StuffIt archive files" "http://downloads.tuxfamily.org/sdtraces/stuffit520.611linux-i386.tar.gz" "external/binwalk/unstuff/tuffit520.611linux-i386.tar.gz" "external/binwalk/unstuff/"
  
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
        BINWALK_PRE_AVAILABLE=0
    
        apt-get install "${INSTALL_APP_LIST[@]}" -y
    
        pip3 install nose 2>/dev/null
        pip3 install coverage 2>/dev/null
        pip3 install pyqtgraph 2>/dev/null
        pip3 install capstone 2>/dev/null
        pip3 install cstruct 2>/dev/null
    
        git clone https://github.com/ReFirmLabs/binwalk.git external/binwalk
    
        if ! command -v yaffshiv > /dev/null ; then
          git clone https://github.com/devttys0/yaffshiv external/binwalk/yaffshiv
          cd ./external/binwalk/yaffshiv/ || exit 1
          python3 setup.py install
          cd "$HOME_PATH" || exit 1
        else
          echo -e "$GREEN""yaffshiv already installed""$NC"
        fi
    
        if ! command -v sasquatch > /dev/null ; then
          git clone https://github.com/devttys0/sasquatch external/binwalk/sasquatch
          CFLAGS="-fcommon -Wno-misleading-indentation" ./external/binwalk/sasquatch/build.sh -y
        else
          echo -e "$GREEN""sasquatch already installed""$NC"
        fi
    
        if ! command -v jefferson > /dev/null ; then
          git clone https://github.com/sviehb/jefferson external/binwalk/jefferson
  
          while read -r TOOL_NAME; do
            print_pip_info "$TOOL_NAME"
          done < ./external/binwalk/jefferson/requirements.txt
  
          pip3 install -r ./external/binwalk/jefferson/requirements.txt
          cd ./external/binwalk/jefferson/ || exit 1
          python3 ./setup.py install
          cd "$HOME_PATH" || exit 1
        else
          echo -e "$GREEN""jefferson already installed""$NC"
        fi
    
        if ! command -v unstuff > /dev/null ; then
          mkdir -p ./external/binwalk/unstuff
          wget -O ./external/binwalk/unstuff/stuffit520.611linux-i386.tar.gz http://downloads.tuxfamily.org/sdtraces/stuffit520.611linux-i386.tar.gz
          tar -zxv -f ./external/binwalk/unstuff/stuffit520.611linux-i386.tar.gz -C ./external/binwalk/unstuff
          cp ./external/binwalk/unstuff/bin/unstuff /usr/local/bin/
        else
          echo -e "$GREEN""unstuff already installed""$NC"
        fi
          
        if ! command -v cramfsck > /dev/null ; then
          if [[ -f "/opt/firmware-mod-kit/trunk/src/cramfs-2.x/cramfsck" ]]; then
            ln -s /opt/firmware-mod-kit/trunk/src/cramfs-2.x/cramfsck /usr/bin/cramfsck
          fi
    
          git clone https://github.com/npitre/cramfs-tools external/binwalk/cramfs-tools
          make -C ./external/binwalk/cramfs-tools/
          install ./external/binwalk/cramfs-tools/mkcramfs /usr/local/bin
          install ./external/binwalk/cramfs-tools/cramfsck /usr/local/bin
        else
          echo -e "$GREEN""cramfsck already installed""$NC"
        fi
    
    
        if ! command -v ubireader_extract_files > /dev/null ; then
          git clone https://github.com/jrspruitt/ubi_reader external/binwalk/ubi_reader
          cd ./external/binwalk/ubi_reader || exit 1
          git reset --hard 0955e6b95f07d849a182125919a1f2b6790d5b51
          python2 setup.py install
          cd "$HOME_PATH" || exit 1
        else
          echo -e "$GREEN""ubi_reader already installed""$NC"
        fi
    
        if ! command -v binwalk > /dev/null ; then
          cd ./external/binwalk || exit 1
          python3 setup.py install
          cd "$HOME_PATH" || exit 1
        else
          echo -e "$GREEN""binwalk already installed""$NC"
          BINWALK_PRE_AVAILABLE=1
        fi
    
        if [[ -d ./external/binwalk ]]; then
          rm ./external/binwalk -r
        fi
    
        if [[ -f "/usr/local/bin/binwalk" && "$BINWALK_PRE_AVAILABLE" -eq 0 ]] ; then
          echo -e "$GREEN""binwalk installed successfully""$NC"
        elif [[ ! -f "/usr/local/bin/binwalk" && "$BINWALK_PRE_AVAILABLE" -eq 0 ]] ; then
          echo -e "$ORANGE""binwalk installation failed - check it manually""$NC"
        fi
      ;;
    esac
  fi
  
  # firmadyne / full system emulation
  
  INSTALL_APP_LIST=()
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || exit 1
  
    print_tool_info "busybox-static" 1
    print_tool_info "fakeroot" 1
    print_tool_info "git" 1
    print_tool_info "dmsetup" 1
    print_tool_info "kpartx" 1
    print_tool_info "nmap" 1
    print_tool_info "snmp" 1
    print_tool_info "nikto" 1
    print_tool_info "snmpcheck" 1
    print_tool_info "uml-utilities" 1
    print_tool_info "util-linux" 1
    print_tool_info "vlan" 1
    print_tool_info "qemu-system-arm" 1
    print_tool_info "qemu-system-mips" 1
    print_tool_info "qemu-system-x86" 1
    print_tool_info "qemu-utils" 1
  
    print_file_info "vmlinux.mipsel" "Firmadyne - Linux kernel 2.6 - MIPSel" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel" "external/firmadyne/binaries/vmlinux.mipsel"
    print_file_info "vmlinux.mipseb" "Firmadyne - Linux kernel 2.6 - MIPSeb" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb" "external/firmadyne/binaries/vmlinux.mipseb"
    print_file_info "zImage.armel" "Firmadyne - Linux kernel 4.1 - ARMel" "https://github.com/firmadyne/kernel-v4.1/releases/download/v1.1/zImage.armel" "external/firmadyne/binaries/zImage.armel"
    print_file_info "console.armel" "Firmadyne - Console - ARMel" "https://github.com/firmadyne/console/releases/download/v1.0/console.armel" "external/firmadyne/binaries/console.armel"
    print_file_info "console.mipseb" "Firmadyne - Console - MIPSeb" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipseb" "external/firmadyne/binaries/console.mipseb"
    print_file_info "console.mipsel" "Firmadyne - Console - MIPSel" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipsel" "external/firmadyne/binaries/console.mipsel"
    print_file_info "libnvram.so.armel" "Firmadyne - libnvram - ARMel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.armel" "external/firmadyne/binaries/libnvram.so.armel"
    print_file_info "libnvram.so.mipseb" "Firmadyne - libnvram - MIPSeb" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipseb" "external/firmadyne/binaries/libnvram.so.mipseb"
    print_file_info "libnvram.so.mipsel" "Firmadyne - libnvram - MIPSel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipsel" "external/firmadyne/binaries/libnvram.so.mipsel"
    print_file_info "fixImage.sh" "Firmadyne fixImage script" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/fixImage.sh" "external/firmadyne/scripts/"
    print_file_info "preInit.sh" "Firmadyne preInit script" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/preInit.sh" "external/firmadyne/scripts/"
   
    if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install the firmadyne dependencies (if not already on the system)?""$NC"
      read -p "(y/N)" -r ANSWER
    elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The firmadyne dependencies (if not already on the system) will be downloaded and be installed!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
  
      mkdir -p external/firmadyne/binaries
      mkdir -p external/firmadyne/scripts
  
      apt-get install "${INSTALL_APP_LIST[@]}" -y
  
      if ! [[ -f "external/firmadyne/binaries/vmlinux.mipsel" ]]; then
        download_file "vmlinux.mipsel" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipsel" "external/firmadyne/binaries/vmlinux.mipsel"
      else
        echo -e "$GREEN""vmlinux.mipsel already installed""$NC"
      fi
  
      if ! [[ -f "external/firmadyne/binaries/vmlinux.mipseb" ]]; then
        download_file "vmlinux.mipseb" "https://github.com/firmadyne/kernel-v2.6/releases/download/v1.1/vmlinux.mipseb" "external/firmadyne/binaries/vmlinux.mipseb"
      else
        echo -e "$GREEN""vmlinux.mipseb already installed""$NC"
      fi
  
      if ! [[ -f "external/firmadyne/binaries/zImage.armel" ]]; then
        download_file "zImage.armel" "https://github.com/firmadyne/kernel-v4.1/releases/download/v1.1/zImage.armel" "external/firmadyne/binaries/zImage.armel"
      else
        echo -e "$GREEN""zImage.armel already installed""$NC"
      fi
  
      if ! [[ -f "external/firmadyne/binaries/console.armel" ]]; then
        download_file "console.armel" "https://github.com/firmadyne/console/releases/download/v1.0/console.armel" "external/firmadyne/binaries/console.armel"
      else
        echo -e "$GREEN""console.armel already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/console.mipseb" ]]; then
        download_file "console.mipseb" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipseb" "external/firmadyne/binaries/console.mipseb"
      else
        echo -e "$GREEN""console.mipseb already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/console.mipsel" ]]; then
        download_file "console.mipsel" "https://github.com/firmadyne/console/releases/download/v1.0/console.mipsel" "external/firmadyne/binaries/console.mipsel"
      else
        echo -e "$GREEN""console.mipsel already installed""$NC"
      fi
  
      if ! [[ -f "external/firmadyne/binaries/libnvram.so.armel" ]]; then
        download_file "libnvram.so.armel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.armel" "external/firmadyne/binaries/libnvram.so.armel"
      else
        echo -e "$GREEN""libnvram.so.armel already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/libnvram.so.mipseb" ]]; then
        download_file "libnvram.so.mipseb" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipseb" "external/firmadyne/binaries/libnvram.so.mipseb"
      else
        echo -e "$GREEN""libnvram.so.mipseb already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/binaries/libnvram.so.mipsel" ]]; then
        download_file "libnvram.so.mipsel" "https://github.com/firmadyne/libnvram/releases/download/v1.0c/libnvram.so.mipsel" "external/firmadyne/binaries/libnvram.so.mipsel"
      else
        echo -e "$GREEN""libnvram.so.mipsel already installed""$NC"
      fi
  
      if ! [[ -f "external/firmadyne/scripts/fixImage.sh" ]]; then
        download_file "fixImage.sh" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/fixImage.sh" "external/firmadyne/scripts/fixImage.sh"
      else
        echo -e "$GREEN""fixImage.sh already installed""$NC"
      fi
      if ! [[ -f "external/firmadyne/scripts/preInit.sh" ]]; then
        download_file "preInit.sh" "https://raw.githubusercontent.com/firmadyne/firmadyne/master/scripts/preInit.sh" "external/firmadyne/scripts/preInit.sh"
      else
        echo -e "$GREEN""preInit.sh already installed""$NC"
      fi
      ;;
    esac
  fi
  
  # routersploit - used for full system emulation

  INSTALL_APP_LIST=()
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || exit 1
    print_git_info "routersploit" "m-1-k-3/routersploit" "The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices. (EMBA fork)"
    print_tool_info "python3-pip" 1
    print_file_info "routersploit_patch" "FirmAE routersploit patch" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/analyses/routersploit_patch" "external/routersploit/docs/routersploit_patch"

    if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install routersploit and the needed dependencies (if not already on the system)?""$NC"
      read -p "(y/N)" -r ANSWER
    elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The routersploit dependencies (if not already on the system) will be downloaded and be installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
  
      apt-get install "${INSTALL_APP_LIST[@]}" -y
 
      git clone https://github.com/m-1-k-3/routersploit.git external/routersploit

      if ! [[ -f "external/routersploit/docs/routersploit_patch" ]]; then
        # is already applied in the used fork (leave this here for future usecases):
        download_file "routersploit_patch" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/analyses/routersploit_patch" "external/routersploit/docs/routersploit_patch"
        patch -f -p1 < docs/routersploit_patch
      else
        echo -e "$GREEN""routersploit_patch already downloaded""$NC"
      fi

      cd external/routersploit || exit 1
      python3 -m pip install -r requirements.txt

      cd "$HOME_PATH" || exit 1

      ;;
    esac
  fi

  # Freetz-NG
  
  INSTALL_APP_LIST=()
  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || exit 1
  
    print_file_info "execstack" "execstack for Freetz-NG" "http://ftp.br.debian.org/debian/pool/main/p/prelink/execstack_0.0.20131005-1+b10_amd64.deb" "external/freetz-ng/execstack_0.0.20131005-1+b10_amd64.deb"
    print_tool_info "python3" 1
    print_tool_info "pv" 1
    print_tool_info "rsync" 1
    print_tool_info "kmod" 1
    print_tool_info "libzstd-dev" 1
    print_tool_info "cmake" 1
    print_tool_info "lib32z1-dev" 1
    print_tool_info "unar" 1
    print_tool_info "inkscape" 1
    print_tool_info "imagemagick" 1
    print_tool_info "subversion" 1
    print_tool_info "git" 1
    print_tool_info "bc" 1
    print_tool_info "wget" 1
    print_tool_info "sudo" 1
    print_tool_info "ccache" 1
    print_tool_info "gcc" 1
    print_tool_info "g++" 1
    print_tool_info "binutils" 1
    print_tool_info "autoconf" 1
    print_tool_info "automake" 1
    print_tool_info "autopoint" 1
    print_tool_info "libtool-bin" 1
    print_tool_info "make" 1
    print_tool_info "bzip2" 1
    print_tool_info "libncurses5-dev" 1
    print_tool_info "libreadline-dev" 1
    print_tool_info "zlib1g-dev" 1
    print_tool_info "flex" 1
    print_tool_info "bison" 1
    print_tool_info "patch" 1
    print_tool_info "texinfo" 1
    print_tool_info "tofrodos" 1
    print_tool_info "gettext" 1
    print_tool_info "pkg-config" 1
    print_tool_info "ecj" 1
    print_tool_info "fastjar" 1
    print_tool_info "perl" 1
    print_tool_info "libstring-crc32-perl" 1
    print_tool_info "ruby" 1
    print_tool_info "gawk" 1
    print_tool_info "libusb-dev" 1
    print_tool_info "unzip" 1
    print_tool_info "intltool" 1
    print_tool_info "libacl1-dev" 1
    print_tool_info "libcap-dev" 1
    print_tool_info "libc6-dev-i386" 1
    print_tool_info "lib32ncurses5-dev" 1
    print_tool_info "gcc-multilib" 1
    print_tool_info "lib32stdc++6" 1
    print_tool_info "libglib2.0-dev" 1
  
    if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install Freetz-NG and the needed dependencies (if not already on the system)?""$NC"
      read -p "(y/N)" -r ANSWER
    elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The Freetz-NG dependencies (if not already on the system) will be downloaded and be installed!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
  
      apt-get install "${INSTALL_APP_LIST[@]}" -y
      if ! grep -q freetzuser /etc/passwd; then
        useradd -m freetzuser
      fi
      download_file "execstack" "http://ftp.br.debian.org/debian/pool/main/p/prelink/execstack_0.0.20131005-1+b10_amd64.deb" "external/execstack_0.0.20131005-1+b10_amd64.deb"
      dpkg -i external/execstack_0.0.20131005-1+b10_amd64.deb
      rm external/execstack_0.0.20131005-1+b10_amd64.deb
      mkdir external/freetz-ng
      chown -R freetzuser:freetzuser external/freetz-ng
      chmod 777 -R external/freetz-ng
      su freetzuser -c "git clone https://github.com/Freetz-NG/freetz-ng.git external/freetz-ng"
      cd external/freetz-ng || exit 1
      if [[ $IN_DOCKER -eq 1 ]]; then
        ln -s /usr/bin/python3 /usr/bin/python
      fi
      sudo -u freetzuser make allnoconfig
      sudo -u freetzuser make
      sudo -u freetzuser make tools
      cd "$HOME_PATH" || exit 1
      chown -R root:root external/freetz-ng
      userdel freetzuser
      ;;
    esac
  fi
fi

# cve-search database for host 

if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] || [[ $CVE_SEARCH -eq 1 ]] || [[ $FULL -eq 1 ]]; then

  print_git_info "cve-search" "cve-search/cve-search" "CVE-Search is a tool to import CVE and CPE into a database to facilitate search and processing of CVEs."
  echo -e "$ORANGE""cve-search will be downloaded.""$NC"

  if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] && [[ $DOCKER_SETUP -eq 0 ]] ; then
    echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install cve-search and mongodb and populate it?""$NC"
    read -p "(y/N)" -r ANSWER
  elif [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] ; then
    ANSWER=("n")
  else
    echo -e "\\n""$MAGENTA""$BOLD""cve-search and mongodb will be downloaded, installed and populated!""$NC"
    ANSWER=("y")
  fi
  
  if [[ "$FORCE" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] ; then
    # we always need the cve-search stuff:
    if [[ -d external/cve-search ]]; then
      rm -r external/cve-search
    fi
  
    git clone https://github.com/cve-search/cve-search.git external/cve-search
    cd ./external/cve-search/ || exit 1

    while read -r TOOL_NAME; do
      print_tool_info "$TOOL_NAME" 1
    done < requirements.system

    while read -r TOOL_NAME; do
      PIP_NAME=$(echo "$TOOL_NAME" | cut -d= -f1)
      TOOL_VERSION=$(echo "$TOOL_NAME" | cut -d= -f3)
      print_pip_info "$PIP_NAME" "$TOOL_VERSION"
    done < requirements.txt

    xargs sudo apt-get install -y < requirements.system
    # shellcheck disable=SC2002
    cat requirements.txt | xargs -n 1 pip install 2>/dev/null
    sed -zE 's/localhost([^\n]*\n[^\n]*27017)/172.36.0.1\1/' ./etc/configuration.ini.sample | tee ./etc/configuration.ini &>/dev/null
    sed -i 's/^\#\ requirepass\ foobared/requirepass\ RedisPassword/g' /etc/redis/redis.conf
  fi
   
  case ${ANSWER:0:1} in
    y|Y )
  
      CVE_INST=1
      echo -e "\\n""$MAGENTA""Check if the cve-search database is already installed.""$NC"
      cd "$HOME_PATH" || exit 1
      cd ./external/cve-search/ || exit 1
      if [[ $(./bin/search.py -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
          CVE_INST=0
          echo -e "\\n""$GREEN""cve-search database already installed - no further action performed.""$NC"
      else
          echo -e "\\n""$MAGENTA""cve-search database not ready.""$NC"
      fi
      if [[ "$CVE_INST" -eq 1 ]]; then
        wget -qO - https://www.mongodb.org/static/pgp/server-4.4.asc | sudo apt-key add -
        echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/4.4 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.4.list
        apt-get update -y
        print_tool_info "mongodb-org" 1
        apt-get install mongodb-org -y
        systemctl daemon-reload
        systemctl start mongod
        systemctl enable mongod
        sed -i 's/bindIp\:\ 127.0.0.1/bindIp\:\ 172.36.0.1/g' /etc/mongod.conf
        systemctl restart mongod.service
        
        if [[ "$FORCE" -eq 0 ]] ; then
          echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and update the cve-search database?""$NC"
          read -p "(y/N)" -r ANSWER
        else
          echo -e "\\n""$MAGENTA""$BOLD""The cve-search database will be downloaded and updated!""$NC"
          ANSWER=("y")
        fi
        case ${ANSWER:0:1} in
          y|Y )
            CVE_INST=1
            echo -e "\\n""$MAGENTA""Check if the cve-search database is already installed.""$NC"
            if [[ $(./bin/search.py -p busybox 2>/dev/null | grep -c ":\ CVE-") -gt 18 ]]; then
              CVE_INST=0
              echo -e "\\n""$GREEN""cve-search database already installed - no further action performed.""$NC"
            else
              echo -e "\\n""$MAGENTA""cve-search database not ready.""$NC"
              echo -e "\\n""$MAGENTA""The installer is going to populate the database.""$NC"
            fi
            # only update and install the database if we have no working database:
            if [[ "$CVE_INST" -eq 1 ]]; then
              /etc/init.d/redis-server start
              ./sbin/db_mgmt_cpe_dictionary.py -p
              ./sbin/db_mgmt_json.py -p
              ./sbin/db_updater.py -f
            else
              echo -e "\\n""$GREEN""$BOLD""CVE database is up and running. No installation process performed!""$NC"
            fi
            cd "$HOME_PATH" || exit 1
            sed -e "s#EMBA_INSTALL_PATH#$(pwd)#" config/emba_updater.init > config/emba_updater
            chmod +x config/emba_updater
            echo -e "\\n""$MAGENTA""$BOLD""The cron.daily update script for EMBA is located in config/emba_updater""$NC"
            echo -e "$MAGENTA""$BOLD""For automatic updates it should be copied to /etc/cron.daily/""$NC"
          ;;
        esac
      fi
      cd "$HOME_PATH" || exit 1
    ;;
  esac
fi

cd "$HOME_PATH" || exit 1

if [[ "$LIST_DEP" -eq 0 ]] || [[ $IN_DOCKER -eq 0 ]] || [[ $DOCKER_SETUP -eq 1 ]] || [[ $FULL -eq 1 ]]; then
  echo -e "\\n""$MAGENTA""$BOLD""Installation notes:""$NC"
  echo -e "\\n""$MAGENTA""INFO: The cron.daily update script for EMBA is located in config/emba_updater""$NC"
  echo -e "$MAGENTA""INFO: For automatic updates it should be copied to /etc/cron.daily/""$NC"
  echo -e "$MAGENTA""INFO: For manual updates just start it via sudo ./config/emba_updater""$NC"

  echo -e "\\n""$MAGENTA""WARNING: If you plan using the emulator (-E switch) your host and your internal network needs to be protected.""$NC"

  echo -e "\\n""$MAGENTA""INFO: Do not forget to checkout current development of EMBA at https://github.com/e-m-b-a.""$NC"
fi

if [[ "$LIST_DEP" -eq 0 ]]; then
  echo -e "$GREEN""EMBA installation finished ""$NC"
fi

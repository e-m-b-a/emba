#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Installs legacy openssl and curl with old TLS and SSL support

IL16_legacy_ssl_curl() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "${HOME_PATH}" || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)

    print_tool_info "build-essential"
    print_tool_info "libpsl-dev"
    print_tool_info "libgsasl-dev"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]]; then
      ANSWER=("n")
    else
      echo -e "\\n${MAGENTA}${BOLD}The live testing dependencies (if not already on the system) will be downloaded and installed!${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
    y | Y)

      apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

      mkdir external/legacy -p
      cd external/legacy || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)

      echo "[*] Installing OpenSSL v1.0.2u with old TLS and SSL support"
      wget https://github.com/openssl/openssl/releases/download/OpenSSL_1_0_2u/openssl-1.0.2u.tar.gz || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      tar -xf openssl-1.0.2u.tar.gz || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      cd openssl-1.0.2u || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      echo "Config openssl v1.0.2u"
      ./config shared --prefix=/external/legacy --openssldir=/external/legacy enable-ssl2 enable-ssl3 enable-ssl3-method || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      echo "make openssl v1.0.2u"
      make || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      echo "make install openssl v1.0.2u"
      make install || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)

      cd "${HOME_PATH}" || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      cd external/legacy || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)

      echo "[*] Installing curl 7.76.1 with old TLS and SSL support"
      wget https://curl.se/download/curl-7.76.1.tar.gz || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      tar -xf curl-7.76.1.tar.gz || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      cd curl-7.76.1 || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      echo "configure curl v7.76.1"
      ./configure --with-ssl=/external/legacy --prefix=/external/legacy --disable-ldap || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      # later versions use --wit-opnssl=....
      ./configure --with-ssl=/external/legacy --prefix=/external/legacy --disable-ldap || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      echo "make curl v7.76.1"
      make || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      echo "make install curl v7.76.1"
      make install || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)
      cd "${HOME_PATH}" || (echo "Could not install EMBA legacy curl and openssl components" && exit 1)

      ;;
    esac
  fi
}

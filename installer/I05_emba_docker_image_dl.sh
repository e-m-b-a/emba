#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description: Download EMBA docker image (only for -d default and full installation)

I05_emba_docker_image_dl() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 0 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] || [[ "${FULL}" -eq 1 ]]; then
    print_tool_info "docker.io" 0 "docker"

    echo -e "\\n""${ORANGE}""${BOLD}""embeddedanalyzer/emba docker image""${NC}"
    echo -e "Description: EMBA docker images used for firmware analysis."

    if command -v docker > /dev/null; then
      f="$(docker manifest inspect "${CONTAINER}" | grep "size" | sed -e 's/[^0-9 ]//g')"
      echo "Download-Size : ""$(("$(( "${f//$'\n'/+}" ))"/1048576))"" MB"
    fi

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""docker.io and the EMBA docker image (if not already on the system) will be downloaded and installed!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        if ! pgrep dockerd; then
          echo -e "\\n""${RED}""${BOLD}""Docker daemon not running! Please check it manually and try again""${NC}"
          exit 1
        fi
        if command -v docker > /dev/null ; then
          export DOCKER_CLI_EXPERIMENTAL=enabled
          echo -e "${ORANGE}""EMBA docker image will be downloaded.""${NC}"
          echo -e "${ORANGE}""CONTAINER VARIABLE SET TO ""${CONTAINER}""${NC}"
          docker pull "${CONTAINER}"
          docker pull "${CONTAINER/:*}:latest"
          sed -i "/image:/c\    image: ${CONTAINER}" docker-compose.yml
          export DOCKER_CLI_EXPERIMENTAL=disabled
          "${DOCKER_COMPOSE[@]}" up --no-start
        else
          echo "Estimated download-Size: ~5500 MB"
          echo -e "${ORANGE}""WARNING: docker command missing - no docker pull possible.""${NC}"
        fi
      ;;
    esac
  fi
}

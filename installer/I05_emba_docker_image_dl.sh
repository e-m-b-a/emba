#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
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
    # print_tool_info "docker.io" 1

    echo -e "\\n""${ORANGE}""${BOLD}""embeddedanalyzer/emba docker image""${NC}"
    echo -e "Description: EMBA docker images used for firmware analysis."

    if command -v docker > /dev/null; then
      # Added error handling to prevent installation failures due to network problems
      if ! f="$(docker manifest inspect "${CONTAINER}" 2>/dev/null | grep "size" | sed -e 's/[^0-9 ]//g')"; then
        echo -e "${ORANGE}The container image size cannot be obtained. The installation process will continue...${NC}"
        echo "Estimated download-Size: ~5500 MB"
      else
        echo "Download-Size : ""$(("$(( "${f//$'\n'/+}" ))"/1048576))"" MB"
      fi
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
          echo -e "${ORANGE}""Checking for EMBA docker image ...""${NC}"
          echo -e "${ORANGE}""CONTAINER VARIABLE SET TO ""${CONTAINER}""${NC}"

          # First, check whether the local mirror exists with the correct base image and version
          if docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "${CONTAINER}"; then
            echo -e "${GREEN}""Found local image ${CONTAINER}, skipping download.""${NC}"
          else
            echo -e "${ORANGE}""Local image not found, attempting to download.""${NC}"
            if ! docker pull "${CONTAINER}"; then
              echo -e "${RED}""Failed to download ${CONTAINER}.""${NC}"
              echo -e "${ORANGE}""Checking if we have any usable local images ...""${NC}"

              # Check if there are any embeddedanalyzer/emba images
              if ! docker images | grep -q "embeddedanalyzer/emba"; then
                echo -e "${RED}""No local EMBA images found. Installation may be incomplete.""${NC}"
                exit 1
              else
                echo -e "${GREEN}""Found alternative local EMBA image, will use that instead.""${NC}"
                # Use the latest local EMBA image
                LOCAL_IMAGE=$(docker images embeddedanalyzer/emba --format "{{.Repository}}:{{.Tag}}" | head -1)
                ORIGINAL_CONTAINER="${CONTAINER}"
                CONTAINER="${LOCAL_IMAGE}"

                # Check if the local image matches what's expected in docker-compose.yml
                if [[ "${ORIGINAL_CONTAINER}" != "${CONTAINER}" ]]; then
                  echo -e "${RED}""WARNING: Using local image ${CONTAINER} instead of ${ORIGINAL_CONTAINER}""${NC}"
                  echo -e "${RED}""This might cause compatibility issues with your docker-compose configuration.""${NC}"
                  read -p "Continue with this image anyway? (y/n): " -n1 -r CONTINUE_ANSWER
                  echo
                  if [[ "${CONTINUE_ANSWER,,}" != "y" ]]; then
                    echo -e "${RED}""Installation aborted by user. Please pull the correct image with:""${NC}"
                    echo -e "${ORANGE}""docker pull ${ORIGINAL_CONTAINER}""${NC}"
                    exit 1
                  fi
                fi
              fi
            fi
          fi

          # Make sure the image has the latest label
          docker tag "${CONTAINER}" "${CONTAINER/:*}:latest"

          # Ensure compatibility between GNU sed and BSD sed
          if sed --version >/dev/null 2>&1; then
            # GNU sed
            sed -i "/image:/c\    image: ${CONTAINER}" docker-compose.yml
          else
            # BSD sed
            sed -i '' "/image:/c\    image: ${CONTAINER}" docker-compose.yml
          fi

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

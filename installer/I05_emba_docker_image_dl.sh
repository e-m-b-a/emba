#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
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

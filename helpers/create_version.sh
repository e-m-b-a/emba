#!/bin/bash
create_version(){
  local VERSION=""
  VERSION="$(echo "$(grep "export EMBA_VERSION=" helpers/helpers_emba_defaults.sh | cut -d\" -f2)"-"$(git describe --always)")"
  echo "${VERSION}" > config/VERSION.txt
}

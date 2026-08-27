# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only

load ../setup.bash

setup() {
  setup_emba_test_env
  # shellcheck source=helpers/helpers_emba_defaults.sh
  source "${HELP_DIR}/helpers_emba_defaults.sh"
  # shellcheck source=modules/Q03_localai_connector.sh
  source "${MOD_DIR}/Q03_localai_connector.sh"
  set_defaults
  export LOCAL_AI_IP="192.0.2.1"
}

teardown() {
  teardown_emba_test_env
}

@test "local_ai_api_url preserves the default endpoint" {
  result="$(local_ai_api_url "models")"
  [ "${result}" = "http://192.0.2.1:8080/v1/models" ]
}

@test "configuration template preserves the scan profile AI mode" {
  export AI_OPTION=2
  # shellcheck source=config/ai_config.env.template
  source "${CONFIG_DIR}/ai_config.env.template"

  [ "${AI_OPTION}" -eq 2 ]
  result="$(local_ai_api_url "models")"
  [ "${result}" = "http://192.168.111.1:8080/v1/models" ]
}

@test "local_ai_api_url uses configured endpoint components" {
  result="$(LOCAL_AI_SCHEME="https" LOCAL_AI_PORT="9443" LOCAL_AI_API_ENDPOINT="/custom" local_ai_api_url "chat/completions")"
  [ "${result}" = "https://192.0.2.1:9443/custom/chat/completions" ]
}

@test "local_ai_api_url normalizes endpoint separators" {
  result="$(LOCAL_AI_API_ENDPOINT="custom/" local_ai_api_url "/models")"
  [ "${result}" = "http://192.0.2.1:8080/custom/models" ]
}

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
#

# shellcheck disable=SC1091

load ../setup.bash

setup() {
  setup_emba_test_env
  # shellcheck source=helpers/helpers_emba_system_emulation.sh
  source "${HELP_DIR}/helpers_emba_system_emulation.sh"
}

teardown() {
  teardown_emba_test_env
}

assert_valid_port() {
  local lPORT="${1}"
  if ! check_for_valid_port "${lPORT}"; then
    printf 'expected valid port: %q\n' "${lPORT}" >&2
    return 1
  fi
}

assert_invalid_port() {
  local lPORT="${1}"
  if check_for_valid_port "${lPORT}"; then
    printf 'expected invalid port: %q\n' "${lPORT}" >&2
    return 1
  fi
}

assert_valid_ip() {
  local lIP_ADDRESS="${1}"
  if ! check_for_valid_ip_address "${lIP_ADDRESS}"; then
    printf 'expected valid IPv4 address: %q\n' "${lIP_ADDRESS}" >&2
    return 1
  fi
}

assert_invalid_ip() {
  local lIP_ADDRESS="${1}"
  if check_for_valid_ip_address "${lIP_ADDRESS}"; then
    printf 'expected invalid IPv4 address: %q\n' "${lIP_ADDRESS}" >&2
    return 1
  fi
}

@test "check_for_valid_port accepts valid ports and leading zeros" {
  local lPORT=""
  local -a lVALID_PORTS=("1" "22" "80" "443" "8080" "65535" "00001" "00080")

  for lPORT in "${lVALID_PORTS[@]}"; do
    assert_valid_port "${lPORT}"
  done
}

@test "check_for_valid_port rejects out-of-range and malformed ports" {
  local lPORT=""
  local -a lINVALID_PORTS=(
    ""
    "0"
    "00000"
    "65536"
    "99999"
    "100000"
    "-1"
    "+80"
    " 80"
    "80 "
    "8 0"
    "80/tcp"
    "0x50"
    "80.0"
    "eighty"
    "80;id"
    "80|id"
    $'80\n'
    $'80\r'
  )

  for lPORT in "${lINVALID_PORTS[@]}"; do
    assert_invalid_port "${lPORT}"
  done
}

@test "check_for_valid_port rejects a missing argument in strict mode" {
  set -u
  run check_for_valid_port
  set +u

  [ "${status}" -eq 1 ]
}

@test "check_for_valid_ip_address accepts valid IPv4 addresses" {
  local lIP_ADDRESS=""
  local -a lVALID_IPS=(
    "0.0.0.0"
    "1.2.3.4"
    "10.0.0.1"
    "100.64.0.1"
    "127.0.0.1"
    "169.254.1.1"
    "172.16.0.1"
    "192.168.1.1"
    "255.0.255.0"
    "255.255.255.255"
  )

  for lIP_ADDRESS in "${lVALID_IPS[@]}"; do
    assert_valid_ip "${lIP_ADDRESS}"
  done
}

@test "check_for_valid_ip_address rejects octets above 255" {
  local lIP_ADDRESS=""
  local -a lINVALID_IPS=(
    "256.0.0.0"
    "0.256.0.0"
    "0.0.256.0"
    "0.0.0.256"
    "999.999.999.999"
  )

  for lIP_ADDRESS in "${lINVALID_IPS[@]}"; do
    assert_invalid_ip "${lIP_ADDRESS}"
  done
}

@test "check_for_valid_ip_address rejects malformed and non-IPv4 input" {
  local lIP_ADDRESS=""
  local -a lINVALID_IPS=(
    ""
    "1.2.3"
    "1.2.3.4.5"
    "1.2.3."
    ".1.2.3"
    "1..2.3"
    "1.2.3.4/24"
    "1.2.3.4:80"
    "localhost"
    "::1"
    "2001:db8::1"
    "1.2.3.4;id"
    "1.2.3.4|id"
    "1.2.3.4&&id"
  )

  for lIP_ADDRESS in "${lINVALID_IPS[@]}"; do
    assert_invalid_ip "${lIP_ADDRESS}"
  done
}

@test "check_for_valid_ip_address rejects octets with leading zeros" {
  local lIP_ADDRESS=""
  local -a lINVALID_IPS=(
    "00.0.0.0"
    "01.2.3.4"
    "1.02.3.4"
    "1.2.03.4"
    "1.2.3.04"
    "0.0.0.000"
  )

  for lIP_ADDRESS in "${lINVALID_IPS[@]}"; do
    assert_invalid_ip "${lIP_ADDRESS}"
  done
}

@test "check_for_valid_ip_address rejects whitespace and control characters" {
  local lIP_ADDRESS=""
  local -a lINVALID_IPS=(
    " 1.2.3.4"
    "1.2.3.4 "
    $'1.2.3.4\n'
    $'1.2.3.4\r'
    $'1.2.3.4\t'
    $'1.2.3.4\n1.2.3.5'
  )

  for lIP_ADDRESS in "${lINVALID_IPS[@]}"; do
    assert_invalid_ip "${lIP_ADDRESS}"
  done
}

@test "check_for_valid_ip_address rejects a missing argument in strict mode" {
  set -u
  run check_for_valid_ip_address
  set +u

  [ "${status}" -eq 1 ]
}

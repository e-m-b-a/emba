#!/usr/bin/env bash
# Internal: The ERR trap calls this function to report on the error location
# right before dying.  See `wickStrictMode` for further details.
#
# $1 - Status from failed command.
#
# Returns nothing.
#
# Source: https://github.com/tests-always-included/wick/blob/b492cc27c49cd416f04c18c5a2dcfafa403b8a37/lib/wick-strict-mode-fail
# License: https://github.com/tests-always-included/wick/blob/master/LICENSE.md

wickStrictModeFail() (
  echo -e "------------------------------------------------------------------------------------------------"
  set +x
  local argsList argsLeft i nextArg

  echo -e "Error detected - status code ${ORANGE}${1}${NC}"
  echo -e "Command:  ${ORANGE}${BASH_COMMAND}${NC}"
  echo -e "Location:  ${ORANGE}${BASH_SOURCE[1]:-unknown}${NC}, line ${ORANGE}${BASH_LINENO[0]:-unknown}${NC}"

  if [[ ${#PIPESTATUS[@]} -gt 1 ]]; then
      echo "Pipe status: " "${PIPESTATUS[@]}"
  fi

  i=$#
  nextArg=$#

  if [[ ${i} -lt ${#BASH_LINENO[@]} ]]; then
    echo "Stack Trace:"
  else
    echo "Stack trace is unavailable"
  fi

  while [[ ${i} -lt ${#BASH_LINENO[@]} ]]; do
    argsList=()

    if [[ ${#BASH_ARGC[@]} -gt ${i} ]] && [[ ${#BASH_ARGV[@]} -ge $(( nextArg + BASH_ARGC[i] )) ]]; then
      for (( argsLeft = BASH_ARGC[i]; argsLeft; --argsLeft )); do
        # Note: this reverses the order on purpose
        argsList[argsLeft]=${BASH_ARGV[nextArg]}
        (( nextArg ++ ))
      done

      if [[ ${#argsList[@]} -gt 0 ]]; then
        printf -v argsList " %q" "${argsList[@]}"
      else
        argsList=""
      fi

      if [[ ${#argsList} -gt 255 ]]; then
        argsList=${argsList:0:250}...
      fi
    else
      argsList=""
    fi

    echo "    [${i}] ${FUNCNAME[i]:+${FUNCNAME[i]}"():" }${BASH_SOURCE[i]}, line ${BASH_LINENO[i - 1]} -> ${FUNCNAME[i]:-${BASH_SOURCE[i]##*/}}${argsList}"
    (( i ++ ))
  done
  echo -e "\n${BLUE}${BOLD}Important: Consider filling out a bug report at https://github.com/e-m-b-a/emba/issues${NC}\n"
  echo -e "------------------------------------------------------------------------------------------------"
)

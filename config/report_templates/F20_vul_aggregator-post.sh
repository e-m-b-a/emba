#!/bin/bash

print_output "[*] Exploitability notes:"
print_output "$(indent "${ORANGE}R$NC - remote exploits")"
print_output "$(indent "${ORANGE}L$NC - local exploits")"
print_output "$(indent "${ORANGE}D$NC - DoS exploits")"
print_output "$(indent "${ORANGE}G$NC - PoC code found on Github (unknown exploit vector)")"

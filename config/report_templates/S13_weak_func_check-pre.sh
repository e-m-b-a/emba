#!/bin/bash

print_output "This module identifies the usage of critical binary functions in firmware via ${ORANGE}objdump${NC}."
print_output "Examples of binary functions are system, strcpy, printf and strcat. These functions are configured in the configuration"
print_output "file config/functions.cfg. The module counts the usages per binary. For strcpy functions it also counts strlen functions"
print_output "right before the strcpy function. Additionally it checks if the binary is a known Linux binary or unknown and probably"
print_output "a vendor binary."
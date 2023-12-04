#!/bin/bash

print_output "This module identifies the usage of critical binary functions in firmware via ${ORANGE}readelf${NC}."
print_output "Examples of binary functions are system, strcpy, printf and strcat. These functions are listed in the configuration"
print_output "file config/functions.cfg."
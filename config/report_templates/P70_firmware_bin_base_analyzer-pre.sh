#!/bin/bash

print_output "This module tries to identify the operating system. Currently, it tries to identify VxWorks, eCos, Adonis, Siprotec, uC/OS and Linux."
print_output "If no Linux operating system is found, then it also tries to identify the target architecture (currently with binwalk only). For Linux operating systems later analysis will do this task."

#!/bin/bash

print_output "This module tries to identify the version of the used Linux kernel. The following sources are tested:"
print_output "$(indent "- Results of module s24")"
print_output "$(indent "- Identified kernel modules in .ko format")"
print_output "$(indent "- Identified kernel modules in .o format")"
print_output "$(indent "- Filesytem path of kernel modules - e.g.: /lib/modules/1.2.3/bla")"
print_ln
print_output "Additionally it checks the identified kernel version with the linux-exploit-suggester (https://github.com/mzet-/linux-exploit-suggester) for known exploits."
print_output "Finally it tests the kernel modules for interesting combination of closed source modules with debugging information. E.g. Non open source modules with debugging information included."
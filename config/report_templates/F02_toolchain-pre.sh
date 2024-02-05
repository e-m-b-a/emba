#!/bin/bash

print_output "The toolchain identification module aggregates multiple sources to help the tester in getting a better understanding of the toolchain that was used to compile/build the firmware."
print_output "For this process EMBA aggregates the following details:"
print_output "$(indent "* The identified kernel version")"
write_link "s24"
print_output "$(indent "* Identifies the kernel release date - getting an idea on how old the used Linux kernel really is")"
write_link "https://mirrors.edge.kernel.org/pub/linux/kernel/"
print_output "$(indent "* EMBA extracts the GCC version from a kernel identifier string")"
write_link "s24"
print_output "$(indent "* EMBA extracts the GCC version from the firmware binaries")"
print_output "$(indent "* Uses an already identified libstdc++ for further GCC identification")"
write_link "https://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html"
print_output "$(indent "* Identifies the GCC release date - getting an idea on how old the used toolchain really is")"
write_link "https://gcc.gnu.org/releases.html"
print_output "$(indent "* EMBA extracts the binary flags from the firmware binaries")"
print_ln
print_output "The following details will help the tester for a better understanding of the original firmware build process. Additionally, these details can support the tester during the build process of a well fitting cross-compilation toolchain."

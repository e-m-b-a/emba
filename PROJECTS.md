
# Community projects

In this document we list all known projects around EMBA and EMBArk. Feel free to open issues or a pull request to list your project also in here.

## EMBA builder

This repository contains code to automate building a dedicated VM for [EMBA](https://www.securefirmware.de/). As EMBA runs best on [Kali Linux](https://www.kali.org/), it uses Kali's own [build script for VM images](https://gitlab.com/kalilinux/build-scripts/kali-vm/) and modifies it to install EMBA.

[Repository](https://github.com/SySS-Research/emba-builder)

## Python modules for EMBA

The Python runner module `S28_python_run` allows users to run Python scripts as EMBA modules. Recommended use cases for this is module code which requires a lot of complex string or data manipulation, as such operations can get quite difficult to implement and later read when using Bash.

[Repository](https://github.com/B1TC0R3/emba/tree/master)

## EMBAbox

This repo provides a Vagrantfile to simply test and to evaluate [EMBA](https://github.com/e-m-b-a/emba)

[Repository](https://github.com/x7-labs/EMBAbox)

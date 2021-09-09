<!-- 
EMBA - EMBEDDED LINUX ANALYZER

Copyright 2020-2021 Siemens AG
Copyright 2020-2021 Siemens Energy AG

EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

EMBA is licensed under GPLv3

Author(s): Michael Messner, Pascal Eckmann
-->

<p align="center">
  <img src="./helpers/emba.svg" width="200"/>
</p>
<p align="center">
  <a href="https://github.com/koalaman/shellcheck"><img src="https://github.com/e-m-b-a/emba/workflows/ShellCheck/badge.svg?branch=master" /></a>
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/Made%20with-Bash-1f425f.svg" /></a>
  <a href="https://github.com/e-m-b-a/emba/blob/master/LICENSE"><img src="https://img.shields.io/github/license/e-m-b-a/emba?label=License"></a>
  <a href="https://github.com/e-m-b-a/emba/graphs/contributors"><img src="https://img.shields.io/github/contributors/e-m-b-a/emba?color=9ea"></a>
  <a href="https://github.com/e-m-b-a/emba/stargazers"><img src="https://img.shields.io/github/stars/e-m-b-a/emba?label=Stars"></a>
  <a href="https://github.com/e-m-b-a/emba/network/members"><img src="https://img.shields.io/github/forks/e-m-b-a/emba?label=Forks"></a>
</p>

# EMBA
## The security analyzer for embedded device firmware

*EMBA* is designed to help penetration testers in analyzing firmware for security vulnerabilities. During such a firmware analysis numerous tools are used, e.g. binwalk, cve-search or yara [(and many others)](https://github.com/e-m-b-a/emba/wiki/Installation#dependencies).

*EMBA* combines these tools under its hood and can be started with one simple command. Afterwards it tests the firmware for possible security risks and interesting areas for further investigation. If the firmware has not yet been extracted, this is done automatically by *EMBA*. No cumbersome installation of all helpers, once the installation script has been executed, you are ready to test your firmware. One of the most important aspects of development is that *EMBA* is easy to use and easy to set up at all times.

*EMBA* is designed to assist penetration testers and not as a standalone tool without human interaction. *EMBA* should provide as much information as possible about the firmware, that the tester can decide on focus areas and is responsible for verifying and interpreting the results. 

----------------------

#### Links to the wiki (more detailed information)

- [Home](https://github.com/e-m-b-a/emba/wiki)
- [Feature overview](https://github.com/e-m-b-a/emba/wiki/Feature-overview)
- [FAQ](https://github.com/e-m-b-a/emba/wiki/FAQ)
- [Installation](https://github.com/e-m-b-a/emba/wiki/Installation)
- [Usage](https://github.com/e-m-b-a/emba/wiki/Usage)
- [Development](https://github.com/e-m-b-a/emba/wiki/Development)

## Installation

Before running *EMBA* make sure, that you have [installed](https://github.com/e-m-b-a/emba/wiki/Installation) all dependencies with the installation script and met the [prerequisites](https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites)

```console
git clone https://github.com/e-m-b-a/emba.git
cd emba
sudo ./installer.sh -d
```

## Usage

---   
### Classic (Docker mode):
```console
sudo ./emba.sh -l ./log -f /firmware
```

---   
### Profile support:
```console
sudo ./emba.sh -l ./log -f /firmware -p ./scan-profiles/default-scan.emba

```
---
### Developer mode (WARNING: EMBA runs on your host and could harm your host!):
```console
./emba.sh -l ./log -f ./firmware -D
```
*WARNING: Before using the developer mode you need a full installation of emba with `sudo ./installer.sh -F`. Such a full installation needs around 14gig of disk space.*

---
*EMBA* supports multiple [arguments](https://github.com/e-m-b-a/emba/wiki/Usage#arguments). For more details check the [wiki](https://github.com/e-m-b-a/emba/wiki/Usage).

## Get involved
The IoT is growing, the development is ongoing, and there are many new features that we want to add.
We welcome [pull requests](https://github.com/e-m-b-a/emba/pulls) and [issues](https://github.com/e-m-b-a/emba/issues) on GitHub.


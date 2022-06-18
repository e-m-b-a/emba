<!-- 
EMBA - EMBEDDED LINUX ANALYZER

Copyright 2020-2022 Siemens AG
Copyright 2020-2022 Siemens Energy AG

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
  <a href="https://hub.docker.com/r/embeddedanalyzer/emba"><img src="https://img.shields.io/docker/pulls/embeddedanalyzer/emba"></a>
  <a href="https://twitter.com/intent/tweet?text=Check%20out%20EMBA%20-%20The%20Firmware%20security%20scanner!%20https://github.com/e-m-b-a/emba"><img src="https://img.shields.io/twitter/url.svg?style=social&url=https%3A%2F%2Fgithub.com%2Fe-m-b-a%2Femba"></a>
</p>

# EMBA
## The security analyzer for embedded device firmware

*EMBA* is designed as the central firmware analysis tool for penetration testers. It supports the complete security analysis process starting with the *firmware extraction* process, doing *static analysis* and *dynamic analysis* via emulation and finally generating a report. *EMBA* automatically discovers possible weak spots and vulnerabilities in firmware. Examples are insecure binaries, old and outdated software components, potentially vulnerable scripts or hard-coded passwords. *EMBA* is a command line tool with the option to generate an easy to use web report for further analysis.

*EMBA* combines multiple established analysis tools and can be started with one simple command. Afterwards it tests the firmware for possible security risks and interesting areas for further investigation. No manual installation of all helpers, once the integrated installation script has been executed, you are ready to test your firmware.

*EMBA* is designed to assist penetration testers and not as a standalone tool without human interaction. *EMBA* should provide as much information as possible about the firmware, that the tester can decide on focus areas and is responsible for verifying and interpreting the results. 

[![Watch EMBA](https://raw.githubusercontent.com/wiki/e-m-b-a/emba/images/youtube-emba.png)](https://youtu.be/_dvdy3klFFY "Watch EMBA")

----------------------

#### Links to the wiki for more detailed information

- [Home](https://github.com/e-m-b-a/emba/wiki)
- [Feature overview](https://github.com/e-m-b-a/emba/wiki/Feature-overview)
- [Installation](https://github.com/e-m-b-a/emba/wiki/Installation)
- [Usage](https://github.com/e-m-b-a/emba/wiki/Usage)
- [FAQ](https://github.com/e-m-b-a/emba/wiki/FAQ)

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
*Note: During installation at least 20GB of disk space is needed*
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
*WARNING: Before using the developer mode you need a full installation of EMBA with `sudo ./installer.sh -F`. This installation mode needs around 15 gigabyte of disk space and is only recommend for development environments.*

---
*EMBA* supports multiple testing and reporting [options](https://github.com/e-m-b-a/emba/wiki/Usage#arguments). For more details check the [wiki](https://github.com/e-m-b-a/emba/wiki/Usage).

## Get involved
The IoT is growing, the development is ongoing, and there are many new features that we want to add.
We welcome [pull requests](https://github.com/e-m-b-a/emba/pulls) and [issues](https://github.com/e-m-b-a/emba/issues) on GitHub.


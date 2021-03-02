<!-- 
emba - EMBEDDED LINUX ANALYZER

Copyright 2020-2021 Siemens AG

emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

emba is licensed under GPLv3

Author(s): Michael Messner, Pascal Eckmann
-->

# emba
### An analyzer for Linux-based firmware of embedded devices

<p align="center">
  <img src="./helpers/emba.svg" width="200"/>
</p>
<p align="center">
  <a href="https://github.com/koalaman/shellcheck"><img src="https://github.com/e-m-b-a/emba/workflows/ShellCheck/badge.svg?branch=master" /></a>
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/Made%20with-Bash-1f425f.svg" /></a>
  <a href="https://github.com/e-m-b-a/emba/blob/master/LICENSE"><img src="https://img.shields.io/github/license/e-m-b-a/emba?label=License"></a>
  <a href="https://github.com/e-m-b-a/emba/stargazers"><img src="https://img.shields.io/github/stars/e-m-b-a/emba?label=Stars"></a>
  <a href="https://github.com/e-m-b-a/emba/network/members"><img src="https://img.shields.io/github/forks/e-m-b-a/emba?label=Forks"></a>
</p>

- [About](#About)
- [Installation](#Installation)
- [Usage](#Usage)

#### Links to the wiki (more detailed information)

- [Home](https://github.com/e-m-b-a/emba/wiki)
  - [Motivation](https://github.com/e-m-b-a/emba/wiki#motivation)
- [Feature overview](https://github.com/e-m-b-a/emba/wiki/Feature-overview)
  - [Emulator](https://github.com/e-m-b-a/emba/wiki/Emulator)
  - [Aggregator](https://github.com/e-m-b-a/emba/wiki/Aggregator)
- [FAQ](https://github.com/e-m-b-a/emba/wiki/FAQ)
- [Installation](https://github.com/e-m-b-a/emba/wiki/Installation)
  - [Classic](https://github.com/e-m-b-a/emba/wiki/Installation#classic-installation)
  - [Docker](https://github.com/e-m-b-a/emba/wiki/Installation#docker-installation)
  - [CVE-Search](https://github.com/e-m-b-a/emba/wiki/Installation#cve-search-installation)
  - [Dependencies](https://github.com/e-m-b-a/emba/wiki/Installation#dependencies)
  - [System tools](https://github.com/e-m-b-a/emba/wiki/Installation#system-tools)
- [Usage](https://github.com/e-m-b-a/emba/wiki/Usage)
  - [Classic](https://github.com/e-m-b-a/emba/wiki/Usage#classic)
  - [Docker](https://github.com/e-m-b-a/emba/wiki/Usage#docker)
  - [Arguments](https://github.com/e-m-b-a/emba/wiki/Usage#arguments)
  - [Live system](https://github.com/e-m-b-a/emba/wiki/Usage#live-systems)
- [Development](https://github.com/e-m-b-a/emba/wiki/Developement)
  - [Structure](https://github.com/e-m-b-a/emba/wiki/Developement#structure-of-emba)
  - [Modules](https://github.com/e-m-b-a/emba/wiki/Developement#development-of-modules)


## About

*Emba* is being developed as a firmware scanner that analyzes Linux-based firmware images, regardless of whether the firmware is a single file or has already been extracted. It should help you identify and focus on interesting areas of firmware images.

Although *emba* is optimized for offline firmware images, it can test both, live systems and extracted images. Additionally, it can also analyze kernel configurations.
*Emba* is designed to assist penetration testers and not as a standalone tool without human interaction. *Emba* should provide as much information as possible about the firmware, the the tester can decide on focus areas and is responsible for verifying and interpreting the results. 

## Installation

Before running *emba* make sure, that you have [installed](https://github.com/e-m-b-a/emba/wiki/Installation) all dependencies.

## Usage

---
### Classic:
```console
./emba.sh -l ./log -f ./firmware
``` 

---   
### Docker:
```console
sudo ./emba.sh -l ./log -f /firmware -D
```

---
You can specify some [arguments](https://github.com/e-m-b-a/emba/wiki/Usage#arguments) and get more [information about usage of *emba* in the wiki](https://github.com/e-m-b-a/emba/wiki/Usage).



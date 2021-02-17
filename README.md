<!-- 
emba - EMBEDDED LINUX ANALYZER

Copyright 2020-2021 Siemens AG

emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

emba is licensed under GPLv3

Author(s): Michael Messner, Pascal Eckmann
-->

# emba - an analyzer for Linux-based firmware of embedded devices

<p align="center">
  <img src="./helpers/emba.png" width="200"/>
</p>
<p align="center">
  <a href="https://github.com/koalaman/shellcheck"><img src="https://github.com/e-m-b-a/emba/workflows/ShellCheck/badge.svg?branch=master" /></a>
  <a href="https://www.gnu.org/software/bash/"><img src="https://img.shields.io/badge/Made%20with-Bash-1f425f.svg" /></a>
  <a href="https://github.com/e-m-b-a/emba/blob/master/LICENSE"><img src="https://img.shields.io/github/license/e-m-b-a/emba?label=License"></a>
  <a href="https://github.com/e-m-b-a/emba/stargazers"><img src="https://img.shields.io/github/stars/e-m-b-a/emba?label=Stars"></a>
  <a href="https://github.com/e-m-b-a/emba/network/members"><img src="https://img.shields.io/github/forks/e-m-b-a/emba?label=Forks"></a>
</p>

- [About](#About)
- [Motivation](#Motivation)
- [Installation](#Installation)
- [Usage](#Usage)

#### Links to the wiki (more detailed information)

- [Home](https://github.com/e-m-b-a/emba/wiki)
- [Feature overview](https://github.com/e-m-b-a/emba/wiki/Feature-overview)
  - [Emulator](https://github.com/e-m-b-a/emba/wiki/Emulator)
  - [Aggregator](https://github.com/e-m-b-a/emba/wiki/Aggregator)
- [FAQ](https://github.com/e-m-b-a/emba/wiki/FAQ)
- [Installation](https://github.com/e-m-b-a/emba/wiki/Installation)
  - [Classic](https://github.com/e-m-b-a/emba/wiki/Installation#classic-installation)
  - [Docker](https://github.com/e-m-b-a/emba/wiki/Installation#docker-installation)
  - [cve-search](https://github.com/e-m-b-a/emba/wiki/Installation#cve-search-installation)
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

_emba_ is being developed as a firmware scanner that analyzes Linux-based firmware images, regardless of whether the firmware is a single file or already been extracted. It should help you to identify and focus on the interesting areas of a huge firmware image.

Although _emba_ is optimized for offline firmware images, it can test both, live systems and extracted images. Additionally, it can also analyze kernel configurations.
_emba_ is designed to assist penetration testers and is not designed as a standalone tool without human interaction. _emba_ should give as much information as possible about the firmware. The tester can then decide on the areas to focus on and is always responsible for verifying and interpreting the results. 

## Motivation

There is a wide variety of different software to analyze Linux firmware, but none it could fulfill our expectiations. Therefore we combined all the good tools in one simple application. The main focus of emba is that it is easy to use, easy to customize and yet find and display all possible weak points. At the start of this project, we decided, that emba should be able to run with only two parameters: path to your firmware (as binary or already extracted) and path to a directory for the generated log files. Using emba should improve your workflow and not take hours to learn to use. During the development, we added a bunch of new features, without dispensing the simplicity. This is also the cause why we stick with bash and have no further plans to rewrite emba in another language. As pentester you are using your terminal on a daily basis and most of us are quite skilled with it. 

## Installation

Before running *emba* make sure, that you have [installed](https://github.com/e-m-b-a/emba/wiki/Installation#docker-installation) all dependencies.

## Usage

---
### Classic:
### `sudo ./emba.sh -l ./log -f ./firmware`   

---   
### Docker:
### `sudo ./emba.sh -l ./log -f /firmware -D`

---
You can specify some [arguments](https://github.com/e-m-b-a/emba/wiki/Usage#arguments) and get more [information about usage of emba in the wiki](https://github.com/e-m-b-a/emba/wiki/Usage).


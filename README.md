<!-- 
emba - EMBEDDED LINUX ANALYZER

Copyright 2020-2021 Siemens AG

emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
welcome to redistribute it under the terms of the GNU General Public License.
See LICENSE file for usage of this software.

emba is licensed under GPLv3

Author(s): Michael Messner, Pascal Eckmann
-->

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

# emba
## The security analyzer for embedded device firmware

*Emba* is designed to help penetration testers gain a lot of knowledge about firmware in a short period of time. As a pentester, you normally use numerous tools, e.g. binwalk, cve-search or yara [(and many others)](https://github.com/e-m-b-a/emba/wiki/Installation#dependencies) and use them to assess the firmware to be tested. 

This is where *emba* comes into play: This tool combines many of the common applications under its hood and can be started with a single command and then scans the firmware for possible security risks. If the firmware has not yet been extracted, this is not an obstacle for *emba*. It will be done automatically. No cumbersome installation of all helpers, once the installation script has been executed, you are ready to test your firmware. One of the most important aspects of development is that Emba is easy to use and easy to set up at all times.

*Emba* is designed to assist penetration testers and not as a standalone tool without human interaction. *Emba* should provide as much information as possible about the firmware, that the tester can decide on focus areas and is responsible for verifying and interpreting the results. 

If you have questions about *emba*, have a look at the [wiki](https://github.com/e-m-b-a/emba/wiki) and if they are not answered there, create an issue.

----------------------

#### Links to the wiki (more detailed information)

- [Home](https://github.com/e-m-b-a/emba/wiki)
- [Feature overview](https://github.com/e-m-b-a/emba/wiki/Feature-overview)
- [FAQ](https://github.com/e-m-b-a/emba/wiki/FAQ)
- [Installation](https://github.com/e-m-b-a/emba/wiki/Installation)
- [Usage](https://github.com/e-m-b-a/emba/wiki/Usage)
- [Development](https://github.com/e-m-b-a/emba/wiki/Development)

## Installation

Before running *emba* make sure, that you have [installed](https://github.com/e-m-b-a/emba/wiki/Installation) all dependencies and met the [prerequisites](https://github.com/e-m-b-a/emba/wiki/Installation#prerequisites)

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
### Profile support:
```console
sudo ./emba.sh -l ./log -f /firmware -p ./scan-profiles/default-scan-docker.emba

```

---
You can specify multiple [arguments](https://github.com/e-m-b-a/emba/wiki/Usage#arguments) and get more [information about usage of *emba* in the wiki](https://github.com/e-m-b-a/emba/wiki/Usage).



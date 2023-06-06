---
name: New Kali Linux release 
about: New release of Kali Linux needs intense testing
title: ''
labels: ''
assignees: ''

---

New Kali Linux is out: https://www.kali.org/blog/kali-linux-2023-2-release/

We need to test EMBA on it

**Testcases:**

Testfirmware: [DLink DIR300](https://ftp.dlink.de/dir/dir-300/archive/driver_software/DIR-300_fw_revb_214b01_ALL_de_20130206.zip)

- [ ] Default/docker installation working with current docker image (`./installer.sh -d`)
  - [ ] dependency check (`./emba.sh -d 1`)
  - [ ] EMBA run with profile default-scan in strict mode (-S)
  - [ ] EMBA run with profile default-scan-emulation in strict mode (-S)
  - [ ] EMBA run with profile full-scan in strict mode (-S)
- [ ] Full installation working (`./installer.sh -F`)
  - [ ] dependency check (`./emba.sh -d 1`)
  - [ ] EMBA run in dev mode with options -s -z -S -D -E -t -W -Q
  - [ ] EMBA run in dev mode with options -s -z -S -D, -c, -E, -t, -W -Q
- [ ] Docker build (`sudo docker-compose build --no-cache --pull`)
  - [ ] dependency check (`./emba.sh -d 2`)
  - [ ] EMBA run with profile default-scan in strict mode (-S)
  - [ ] EMBA run with profile default-scan-emulation in strict mode (-S)
  - [ ] EMBA run with profile full-scan in strict mode (-S)

**Priority issue**
Are you already a [Sponsor]? - [Y/N]

**Additional context**
Add any other context about the problem here.

[Sponsor]: https://github.com/sponsors/e-m-b-a

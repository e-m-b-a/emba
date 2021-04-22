#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Aggregates all found version numbers together from R09, S09, S25 and S115 and searches with cve-search for all CVEs, 
#               then it lists exploits that could possible be used for the firmware.

F19_cve_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final CVE aggregator"
  
  # we need:
  # apt-get install bc
  # sudo pip3 install cve-searchsploit
  # https://github.com/cve-search/cve-search

  # set it up
  PATH_CVE_SEARCH="./external/cve-search/bin/search.py"
  if ! [[ -d "$LOG_DIR"/aggregator ]] ; then
    mkdir "$LOG_DIR"/aggregator
  fi
  KERNELV=0
  HIGH_CVE_COUNTER=0
  MEDIUM_CVE_COUNTER=0
  LOW_CVE_COUNTER=0
  CVE_SEARCHSPLOIT=0

  CVE_AGGREGATOR_LOG="f19_cve_aggregator.txt"
  if [[ -f "$LOG_DIR"/r09_firmware_base_version_check.txt ]]; then 
    FW_VER_CHECK_LOG="r09_firmware_base_version_check.txt"
  else
    FW_VER_CHECK_LOG="s09_firmware_base_version_check.txt"
  fi
  KERNEL_CHECK_LOG="s25_kernel_check.txt"
  EMUL_LOG="s115_usermode_emulator.txt"
  CVE_MINIMAL_LOG="$LOG_DIR"/aggregator/CVE_minimal.txt
  EXPLOIT_OVERVIEW_LOG="$LOG_DIR"/aggregator/exploits-overview.txt

  if [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[*] Aggregate vulnerability details"

    get_kernel_check
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ ${#VERSIONS_KERNEL[@]} -ne 0 ]]; then
      # then we have found a kernel in our s25 kernel module
      KERNELV=1
    fi

    get_firmware_base_version_check
    get_usermode_emulator

    aggregate_versions
    
    # Mongo DB is running on Port 27017. If not we can't check CVEs
    if [[ $(netstat -ant | grep -c 27017) -eq 0 && $IN_DOCKER -eq 0 ]]; then
      print_output "[*] Trying to start the vulnerability database"
      systemctl restart mongod
      sleep 2
    fi

    if [[ $(netstat -ant | grep -c 27017) -gt 0 ]]; then
      if command -v cve_searchsploit > /dev/null ; then
        CVE_SEARCHSPLOIT=1
      fi
      generate_cve_details
      generate_special_log
    else
      print_output "[-] MongoDB not running on port 27017."
      print_output "[-] CVE checks not possible!"
      print_output "[-] Have you installed all the needed dependencies?"
      print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
    fi
  else
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Run the installer or install it from here: https://github.com/cve-search/cve-search."
    print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
  fi

  module_end_log "${FUNCNAME[0]}" "$CVE_COUNTER"
}

prepare_version_data() {
    #print_output "$VERSION_lower"
    # we try to handle as many version strings as possible through these generic rules
    VERSION_lower="$(echo "$VERSION" | tr '[:upper:]' '[:lower:]')"
    # tab -> space
    # remove multiple spaces
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/[[:space:]]\+/\ /g')"
    VERSION_lower="${VERSION_lower//\ in\ extracted\ firmware\ files\ \(static\)\./\ }"
    VERSION_lower="${VERSION_lower//\ in\ original\ firmware\ file\ (static)\./\ }"
    VERSION_lower="${VERSION_lower//\ in\ extraction\ logs\ (static)\./\ }"
    VERSION_lower="${VERSION_lower//\ in\ binwalk\ logs\ (static)\./\ }"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\ in\ binary\ .*\./\ /g')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\ in\ kernel\ image\ .*\./\ /g')"
    # GNU gdbserver (GDB)
    VERSION_lower="${VERSION_lower//gnu\ gdbserver\ /gdb\ }"
    VERSION_lower="${VERSION_lower//(gdb)/}"
    #udevadm -> systemd
    VERSION_lower="${VERSION_lower//udevadm/systemd}"
    # some - -> space
    VERSION_lower="${VERSION_lower//acpid-/acpid\ }"
    VERSION_lower="${VERSION_lower//linux-/linux\ }"
    # alsactl, amixer -> alsa
    VERSION_lower="${VERSION_lower//alsactl/alsa}"
    VERSION_lower="${VERSION_lower//amixer/alsa}"
    #sudoreplay -> sudo
    VERSION_lower="${VERSION_lower//sudoreplay/sudo}"
    #visudo -> sudo
    VERSION_lower="${VERSION_lower//visudo/sudo}"
    # VIM - Vi IMproved 1.2
    VERSION_lower="${VERSION_lower//vim\ -\ vi\ improved/vim}"
    #zic.c
    VERSION_lower="${VERSION_lower//zic\.c/zic}"
    #bzip2, a block-sorting file compressor.  Version 1.0.6, 
    VERSION_lower="${VERSION_lower//bzip2,\ a\ block-sorting\ file\ compressor\.\ version/bzip2}"
    VERSION_lower="${VERSION_lower//bzip2recover/bzip2}"
    # gnutls
    VERSION_lower="${VERSION_lower//enabled\ gnutls/gnutls}"
    VERSION_lower="${VERSION_lower//project-id-version:\ gnutls/gnutls}"
    #jQuery JavaScript Library v1.4.3
    VERSION_lower="${VERSION_lower//jquery\ javascript\ library\ v/jquery\ }"
    # GNU Midnight Commander 
    VERSION_lower="${VERSION_lower//gnu\ midnight\ commander/midnight_commander}"
    #xl2tpd version:  xl2tpd-1.3.6
    VERSION_lower="${VERSION_lower//xl2tpd\ version\:\ xl2tpd-/xl2tp\ }"
    VERSION_lower="${VERSION_lower//xl2tpd\ server\ xl2tpd-/xl2tpd\ }"
    VERSION_lower="${VERSION_lower//goahead\ /goahead\ }"
    # nc.traditional:strict:"\[v[0-9]\.[0-9]+-[0-9]+\]$"
    VERSION_lower="${VERSION_lower//nc.traditional\ \[v/nc.traditional\ }"
    # sqlite3 -> sqlite
    VERSION_lower="${VERSION_lower//sqlite3/sqlite}"
    # dnsmasq- -> dnsmasq 
    VERSION_lower="${VERSION_lower//dnsmasq-/dnsmasq\ }"
    # Compiled\ with\ U-Boot -> u-boot
    VERSION_lower="${VERSION_lower//compiled\ with\ u-boot/u-boot }"
    #tcpdump.4.6.2 version
    VERSION_lower="${VERSION_lower//tcpdump\./tcpdump\ }"
    #ntpd\ -\ standard\ NTP\ query\ program\ -\ Ver\.
    VERSION_lower="${VERSION_lower//ntpd\ -\ ntp\ daemon\ program\ -\ ver\.\ /ntpd\ }"
    VERSION_lower="${VERSION_lower//ntpq\ -\ standard\ ntp\ query\ program\ -\ ver\.\ /ntpq\ }"
    #This is SMTPclient Version
    VERSION_lower="${VERSION_lower//this\ is\ smtpclient/smtpclient}"
    #btconfig - BTCONFIG Tool ver
    VERSION_lower="${VERSION_lower//-\ btconfig\ tool\ ver/}"
    # hciemu - HCI emulator ver 
    VERSION_lower="${VERSION_lower//-\ hci\ emulator\ ver/}"
    # hcitool - HCI Tool ver 
    VERSION_lower="${VERSION_lower//-\ hci\ tool\ ver/}"
    # sdptool - SDP tool 
    VERSION_lower="${VERSION_lower//-\ sdp\ tool/}"
    # iputils-sss
    VERSION_lower="${VERSION_lower//iputils-sss/iputils\ }"
    VERSION_lower="${VERSION_lower//iproute2-ss/iproute2\ }"
    #nettle-hash\ (nettle\ -> nettle
    VERSION_lower="${VERSION_lower//nettle-hash\ ./}"
    # if we have a version string like "binary version v1.2.3" we have to remove the version and the v:
    VERSION_lower="${VERSION_lower//\ version\:/}"
    VERSION_lower="${VERSION_lower//version\ /}"
    # ubiXYZ -> mtd-utils
    VERSION_lower="${VERSION_lower//ubinfo/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiattach/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubidetach/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubimkvol/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubirmvol/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiblock/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiupdatevol/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubicrc32/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubinize/mtd-utils}"
    VERSION_lower="${VERSION_lower//ubiformat/mtd-utils}"
    VERSION_lower="${VERSION_lower//mtdinfo/mtd-utils}"
    VERSION_lower="${VERSION_lower//nandwrite/mtd-utils}"
    VERSION_lower="${VERSION_lower//nanddump/mtd-utils}"
    VERSION_lower="${VERSION_lower//flash_erase/mtd-utils}"
    # zlib:binary:"deflate\ [0-9]\.[0-9]+\.[0-9]+\ Copyright.*Mark\ Adler"
    # zlib:binary:"inflate\ [0-9]\.[0-9]+\.[0-9]+\ Copyright.*Mark Adler"
    VERSION_lower="${VERSION_lower//deflate/zlib}"
    VERSION_lower="${VERSION_lower//inflate/zlib}"
    # e2fsprogs
    VERSION_lower="${VERSION_lower//debugfs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//dumpe2fs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//e2fsck/e2fsprogs}"
    VERSION_lower="${VERSION_lower//e2image/e2fsprogs}"
    VERSION_lower="${VERSION_lower//mke2fs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//resize2fs/e2fsprogs}"
    VERSION_lower="${VERSION_lower//tune2fs/e2fsprogs}"
    #ntfslabel -> ntfs-3g
    VERSION_lower="${VERSION_lower//ntfslabel/ntfs-3g}"
    #i2cXYZ -> i2c-tools
    VERSION_lower="${VERSION_lower//i2cdetect/i2c-tools}"
    VERSION_lower="${VERSION_lower//i2cdump/i2c-tools}"
    VERSION_lower="${VERSION_lower//i2cget/i2c-tools}"
    VERSION_lower="${VERSION_lower//i2cset/i2c-tools}"
    #manxyz -> man-db
    VERSION_lower="${VERSION_lower//mandb/man-db}"
    VERSION_lower="${VERSION_lower//manpath/man-db}"
    VERSION_lower="${VERSION_lower//catman/man-db}"
    VERSION_lower="${VERSION_lower//globbing/man-db}"
    VERSION_lower="${VERSION_lower//lexgrog/man-db}"
    #jfsxyz -> jfsutils
    VERSION_lower="${VERSION_lower//jfs_fscklog/jfsutils}"
    VERSION_lower="${VERSION_lower//jfs_tune/jfsutils}"
    # expat_1.1.1 -> expat 1.1.1
    VERSION_lower="${VERSION_lower//expat_/expat\ }"
    #file-
    VERSION_lower="${VERSION_lower//file-/file\ }"
    #libpcre.1.2.3
    VERSION_lower="${VERSION_lower//libpcre\.so\./pcre\ }"
    VERSION_lower="${VERSION_lower//pppd\.so\./pppd\ }"
    #pinentry-curses (pinentry)
    VERSION_lower="${VERSION_lower//pinentry-curses\ (pinentry)/pinentry}"
    # lsusb (usbutils)
    VERSION_lower="${VERSION_lower//lsusb\ (usbutils)/usbutils}"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/nc\.traditional\ \[v\ /nc.traditional\ /g')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/getconf\ (.*)/getconf/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/localedef\ (.*)/localedef/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/pt_chown\ (.*)/pt_chown/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/rpcinfo\ (.*)/rpcinfo/')"
    #This is perl 5, version 20, subversion 0 (v5.20.0) built
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/this\ is\ perl\ ([0-9]),\ ([0-9][0-9]),\ sub([0-9])/perl\ \1\.\2\.\3/')"
    #"GNU\ gdb\ \(Debian\ [0-9]\.[0-9]+-[0-9]\)\ "
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/gnu\ gdb\ \(debian\ ([0-9]\.[0-9]+-[0-9]+\))\ /gdb\ \1/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/this\ is\ perl.*.v/perl\ /')"
    #gpg (GnuPG) 2.2.17
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/g.*\ (gnupg)/gnupg/')"
    #Wireless-Tools version 29
    VERSION_lower="${VERSION_lower//wireless-tools\ /wireless_tools\ }"
    VERSION_lower="${VERSION_lower//i.*\ wireless_tools\ /wireless_tools\ }"
    # apt-Version 1.2.3
    VERSION_lower="${VERSION_lower//apt-/apt\ }"
    # remove the v in something like this: "space v[number]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\ v([0-9]+)/\ \1/g')"
    # "mkfs\.jffs2\ revision\ [0-9]\.[0-9]\.[0-9]\.[0-9]"
    VERSION_lower="${VERSION_lower//revision\ /}"
    # mkfs.jffs2: error!: revision 1.60
    VERSION_lower="${VERSION_lower//:\ error!:/}"
    #"Dropbear\ sshd\ v20[0-9][0-9]\.[0-9][0-9]"
    VERSION_lower="${VERSION_lower//dropbear\ sshd/dropbear_ssh}"
    #3.0.10 - $Id: ez-ipupdate.c,v 1.44 (from binary 3322ip) found in qemu_3322ip.txt.
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/([0-9]\.[0-9]\.[0-9]+)\ -\ .*ez\-ipupdate\.c,v\ [0-9]\.[0-9][0-9]/ez-ipupdate \1/')"
    #"ndisc6\:\ IPv6\ Neighbor\/Router\ Discovery\ userland\ tool\ [0-9]\.[0-9]\.[0-9]\ "
    VERSION_lower="${VERSION_lower//\:\ ipv6\ neighbor\/router\ discovery\ userland\ tool/}"
    #"ucloud_v2\ ver\.[0-9][0-9][0-9]"
    VERSION_lower="${VERSION_lower//ver\./}"
    # rdnssd\:\ IPv6\ Recursive\ DNS\ Server\ discovery\ Daemon\
    VERSION_lower="${VERSION_lower//\:\ ipv6\ recursive\ dns\ server\ discovery\ daemon/}"
    #NETIO\ -\ Network\ Throughput\ Benchmark,\ Version
    VERSION_lower="${VERSION_lower//-\ network\ throughput\ benchmark\,\ /}"
    #ntpd\ -\ NTP\ daemon\ program\ -\ Ver\.
    VERSION_lower="${VERSION_lower//-\ ntp\ daemon\ program\ -/}"
    # GNU bash, 4.3.39
    VERSION_lower="${VERSION_lower//gnu\ bash,\ /bash\ }"
    # FUSE library version: 2.9.4
    VERSION_lower="${VERSION_lower//fuse\ library/fuse}"
    #Linux strongSwan 5.2.2 
    VERSION_lower="${VERSION_lower//linux\ strongswan/strongswan}"
    # NET-SNMP\ version:\ \ 
    #VERSION_lower="${VERSION_lower//net-snmp/net-snmp}"
    #igmpproxy, Version 0.1
    VERSION_lower="${VERSION_lower//,/}"
    #flash_eraseall $ 1.1 $
    VERSION_lower="${VERSION_lower//\$/}"
    VERSION_lower="${VERSION_lower//\"/}"
    #radlogin.cv
    VERSION_lower="${VERSION_lower//radlogin\.cv/radlogin}"
    #event log utility
    VERSION_lower="${VERSION_lower//event\ log\ utility/event_log_utility}"
    #message manager utility
    VERSION_lower="${VERSION_lower//message\ manager\ utility/message_manager_utility}"
    # BoosterMainFunction:305
    VERSION_lower="${VERSION_lower//boostermainfunction:305/booster}"
    VERSION_lower="${VERSION_lower//:/}"
    VERSION_lower="${VERSION_lower//--\ /}"
    VERSION_lower="${VERSION_lower//-\ /}"
    #mini_httpd/1.19
    VERSION_lower="${VERSION_lower/\//\ }"
    #OpenLDAP:\ ldapsearch
    VERSION_lower="${VERSION_lower/openldap\ ldapsearch/openldap}"
    #Beceem\ CM\ Server\
    VERSION_lower="${VERSION_lower//beceem\ cm\ server/beceem}"
    VERSION_lower="${VERSION_lower//beceem\ cscm\ command\ line\ client/beceem}"
    # CLIENT\ libcurl\
    VERSION_lower="${VERSION_lower//client\ libcurl/libcurl}"
    #Intel SDK for UPnP devices /1.2
    VERSION_lower="${VERSION_lower//intel\ sdk\ for\ upnp\ devices\ \ /portable_sdk_for_upnp\ }"
    # busybox 1.00-pre2 -> we ignore the pre
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/busybox\ ([0-9]\.[0-9][0-9])-pre[0-9]/busybox\ \1/g')"
    # GNU C Library (AuDis-V04.56) stable release version 2.23
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/gnu\ c\ library\ .*\ release/glibc/')"
    # (Debian EGLIBC 2.13-38+deb7u11) 2.13
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(eglibc)/eglibc/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(.*\ eglibc\ .*)/eglibc/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(debian\ glibc.*)/glibc/')"
    #vxworks 7 sr0530 -> vxworks 7:sr0530
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/vxworks\ ([0-9])\ sr([0-9]+)/vxworks\ \1:sr\2/g')"
    #vxworks5.5.1 -> no space
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/vxworks([0-9]\.[0-9]+\.[0-9]+)/vxworks\ \1/g')"
    #VxWorks operating system version "5.5.1"
    VERSION_lower="${VERSION_lower//vxworks\ operating\ system/vxworks}"
    #OpenSSH_7.8p1 -> openssh 7.8:p1 
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/openssh_([0-9])\.([0-9])([a-z][0-9])/openssh\ \1\.\2:\3/g')"
    #socat 2.0.0-b4 -> socat 2.0.0:b4 
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/socat\ ([0-9]\.[0-9]\.[0-9])-([a-z][0-9])/socat\ \1:\2/g')"
    # pppd 2.4.2b3
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/pppd\ ([0-9]\.[0-9]\.[0-9])([a-z][0-9])/pppd\ \1:\2/g')"
    # ntpd 4.2.8p13 -> ntp 4.2.8:p13
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ntp[dq]\ ([0-9]\.[0-9]\.[0-9])([a-z][0-9])/ntp\ \1:\2/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ntpdc\ vendor-specific.*query.*([0-9]\.[0-9]\.[0-9])([a-z][0-9])/ntp\ \1:\2/g')"
    # ntpdate 4.2.8p13 -> ntp 4.2.8:p13
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/ntpdate\ ([0-9]\.[0-9]\.[0-9])([a-z]([0-9]))/ntp\ \1:\2/g')"
    # FreeBSD 12.1-RELEASE-p8  -> FreeBSD 12.1:p8 
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/freebsd\ ([0-9]+\.[0-9]+)-release-([a-z]([0-9]+))/freebsd\ \1:\2/g')"
    # unzip .... info-zip -> info-zip
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zipinfo\ ([0-9]\.[0-9][0-9])\ .*\ info-zip.*/info-zip:zip\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/unzip\ ([0-9]\.[0-9][0-9])\ .*\ by\ info-zip.*/info-zip:unzip\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zip\ ([0-9]\.[0-9])\ .*\ by\ info-zip.*/info-zip:zip\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zipcloak\ ([0-9]\.[0-9])\ .*\ by\ info-zip.*/info-zip:zipcloak\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/zipnote\ ([0-9]\.[0-9])\ .*\ by\ info-zip.*/info-zip:zipnote\ \1/g')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/([a-z]\ UnZip),/info-zip:zip/')"
    #mdns repeater (1.10)
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/mdns\ repeater\ \(([0-9]\.[0-9][0-9])\)/mdnsrepeater\ \1/g')"
    #management console agent 1.5 (c) ubiquiti networks inc
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/management\ console\ agent\ ([0-9]\.[0-9]).*ubiquiti\ networks/ubiquiti:console_agent\ \1/g')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/multipurpose.*control\ daemon\ ([0-9]\.[0-9]).*ubiquiti/ubiquiti:control_daemon\ \1/g')"
    #avahi::"avahi-.*[0-9]\.[0-9]\.[0-9][0-9]$"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/avahi-.*\ ([0-9]\.[0-9]\.[0-9][0-9])/avahi\ \1/g')"
    #server debian wheezy upnp/1.1 miniupnpd/2.1
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/server.*upnp.*miniupnpd\/([0-9]\.[0-9])/miniupnpd\ \1/g')"
    # linux -> kernel (we find the CVEs in the database with kernel as search string)
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^linux\ ([0-9])/kernel\ \1/')"
    # Siprotec 5 firmware has a version identifier like FWAOS_V01.11.01.123
    VERSION_lower="${VERSION_lower//fwaos_v/siprotec_5\ }"
    #isc-dhclient-4.1-ESV-R8 -> isc:dhcp_client
    VERSION_lower="${VERSION_lower//isc-dhclient-/isc:dhcp_client\ }"
    VERSION_lower="${VERSION_lower//internet\ systems\ consortium\ dhcp\ client\ /isc:dhcp_client\ }"
    #jq commandline json processor [5a49c82-dirty]
    #VERSION_lower="${VERSION_lower//jq\ commandline\ json\ processor\ \[/jq_project:jq\ }"
    #Squid\ Cache:\ Version\ [0-9]\.[0-9]\.[0-9]$"
    VERSION_lower="${VERSION_lower//squid\ cache:/squid-cache:squid}"
    #tar (GNU tar) 1.23
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ tar)/gnu:tar/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ findutils)/gnu:findutils/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ groff)/gnu:groff/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ sed)/gnu:sed/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ mtools)/gnu:mtools/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ cpio)/gnu:cpio/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ texinfo)/gnu:texinfo/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ gettext-runtime)/gnu:gettext-runtime/')"
    # handle grub version 2:
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(grub)\ 2/grub2\ 2/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(grub)/grub/')"
    VERSION_lower="${VERSION_lower//gnu\ sed/gnu:sed}"
    VERSION_lower="${VERSION_lower//gnu\ make/gnu:make}"
    VERSION_lower="${VERSION_lower//gnu\ nano/gnu:nano}"
    VERSION_lower="${VERSION_lower//loadkeys\ von\ kbd/kbd-project:kbd}"
    VERSION_lower="${VERSION_lower//loadkeys\ from\ kbd/kbd-project:kbd}"
    VERSION_lower="${VERSION_lower//kbd_mode\ from\ kbd/kbd-project:kbd}"
    #dpkg-ABC -> dpkg
    VERSION_lower="${VERSION_lower//dpkg-divert/debian:dpkg}"
    VERSION_lower="${VERSION_lower//dpkg-split/debian:dpkg}"
    VERSION_lower="${VERSION_lower//dpkg-deb/debian:dpkg}"
    VERSION_lower="${VERSION_lower//dpkg-trigger/debian:dpkg}"
    # ncurses -> gnu:ncurses
    VERSION_lower="${VERSION_lower//ncurses/gnu:ncurses}"
    #VERSION_lower="${VERSION_lower//(gnu\ binutils.*)/gnu:binutils}"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ binutils.*)/gnu:binutils/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ grep.*)/gnu:grep/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ diffutils.*)/gnu:diffutils/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ coreutils.*)/gnu:coreutils/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(gnu\ sharutils.*)/gnu:sharutils/')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/(xz\ utils.*)/xz-utils/')"
    #zend engine 2.4.0 copyright (c) 1998-2014 zend technologies
    VERSION_lower="${VERSION_lower//zend\ engine/zend:engine}"
    #D-Bus Message Bus Daemon 1.6.8
    VERSION_lower="${VERSION_lower//d-bus\ message\ bus\ daemon/freedesktop:dbus}"
    VERSION_lower="${VERSION_lower//d-bus\ socket\ cleanup\ utility/freedesktop:dbus}"
    VERSION_lower="${VERSION_lower//d-bus\ uuid\ generator/freedesktop:dbus}"
    #Roaring Penguin PPPoE Version
    VERSION_lower="${VERSION_lower//roaring\ penguin\ pppoe/roaring_penguin:pppoe}"
    #upnp controlpoint 1.0
    VERSION_lower="${VERSION_lower//upnp\ controlpoint/upnp_controlpoint}"
    #----welcome to realtek camera tool.
    VERSION_lower="${VERSION_lower//----welcome\ to\ realtek\ camera\ tool\./realtek_camera_tool}"
    #remove '
    VERSION_lower="${VERSION_lower//\'/}"
    # Ralink\ DOT1X\ daemon,\ version\ = '
    VERSION_lower="${VERSION_lower//ralink\ dot1x\ daemon\ \=\ /ralink-dot1x\ }"
    #his\ is\ WiFiDog\ 
    VERSION_lower="${VERSION_lower//this\ is\ wifidog/wifidog}"
    # letz try to handle something like 1p2 -> 1:p2
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/([0-9])([a-z]([0-9]))/\1:\2/g')"

    # final cleanup of start and ending
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/-git$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/-beta$//')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^-//')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^_//')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/-$//')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/_$//')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/^\ //')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\ $//')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\.$//')"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\]$//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/[)$]//')"
    #print_output "$VERSION_lower"

    # sometimes we get "Linux kernel x.yz.ab -> remove the first part of it
    if [[ $VERSION_lower == *linux\ kernel* ]]; then
      VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f2-3)"
    fi

    # now we should have the name and the version in the first two coloumns:
    VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f1-2)"
    # check if we have some number in it ... without a number we have no version info and we can drop this entry ...
    if [[ $VERSION_lower =~ [0-9] ]]; then
      #VERSIONS_CLEANED+=( "$VERSION_lower" )
      # for multi threading we have to go via a temp file
      echo "$VERSION_lower" >> "$LOG_DIR"/aggregator/versions.tmp
    fi
}

aggregate_versions() {
  sub_module_title "Software inventory generation."

  # initial output - probably we will remove it in the future
  # currently it is very helpful
  print_output "[*] Software inventory initial overview:"
  for VERSION in "${VERSIONS_BASE_CHECK[@]}"; do
    print_output "[+] Found Version details (base check): ""$VERSION"
  done
  for VERSION in "${VERSIONS_STAT_CHECK[@]}"; do
    print_output "[+] Found Version details (statical check): ""$VERSION"
  done
  for VERSION in "${VERSIONS_EMULATOR[@]}"; do
    print_output "[+] Found Version details (emulator): ""$VERSION"
  done
  for VERSION in "${VERSIONS_KERNEL[@]}"; do
    print_output "[+] Found Version details (kernel): ""$VERSION"
  done

  print_output ""
  VERSIONS_AGGREGATED=("${VERSIONS_BASE_CHECK[@]}" "${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}" "${VERSIONS_STAT_CHECK[@]}")
  for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    # remove color codes:
    VERSION=$(echo "$VERSION" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
    # as this is just a background job we always thread it
    prepare_version_data &
    WAIT_PIDS_F19+=( "$!" )
  done

  wait_for_pid "${WAIT_PIDS_F19[@]}"

  # sorting and unique our versions array:
  #eval "VERSIONS_CLEANED=($(for i in "${VERSIONS_CLEANED[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  mapfile -t VERSIONS_CLEANED < <(sort -u "$LOG_DIR"/aggregator/versions.tmp)
  rm "$LOG_DIR"/aggregator/versions.tmp 2>/dev/null

  if [[ ${#VERSIONS_CLEANED[@]} -ne 0 ]]; then
    print_output "[*] Software inventory aggregated:"
    for VERSION in "${VERSIONS_CLEANED[@]}"; do
      print_output "[+] Found Version details (aggregated): ""$VERSION"
    done
  else
      print_output "[-] No Version details found."
  fi
  print_output ""
}

generate_special_log() {
  sub_module_title "Generate special log files."

  if [[ "$CVE_COUNTER" -gt 0 ]]; then
    readarray -t FILES < <(find "$LOG_DIR"/aggregator/ -type f)
    print_output ""
    print_output "[*] Generate CVE log file in $CVE_MINIMAL_LOG:\\n"
    for FILE in "${FILES[@]}"; do
      NAME=$(basename "$FILE" | sed -e 's/\.txt//g' | sed -e 's/_/\ /g')
      CVE_VALUES=$(grep ^CVE "$FILE" | cut -d: -f2 | tr -d '\n' | sed -r 's/[[:space:]]+/, /g' | sed -e 's/^,\ //') 
      if [[ -n $CVE_VALUES ]]; then
        print_output "[*] CVE details for ${GREEN}$NAME${NC}:\\n"
        print_output "$CVE_VALUES"
        echo -e "\n[*] CVE details for ${GREEN}$NAME${NC}:" >> "$CVE_MINIMAL_LOG"
        echo "$CVE_VALUES" >> "$CVE_MINIMAL_LOG"
        print_output ""
      fi
    done
  fi

  if [[ "$EXPLOIT_COUNTER" -gt 0 ]]; then
    print_output ""
    print_output "[*] Generate minimal exploit summary file in $EXPLOIT_OVERVIEW_LOG:\\n"
    mapfile -t EXPLOITS_AVAIL < <(grep "Exploit\ available" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r)
    for EXPLOIT_ in "${EXPLOITS_AVAIL[@]}"; do
      # remove color codes:
      EXPLOIT_=$(echo "$EXPLOIT_" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
      CVSS_VALUE=$(echo "$EXPLOIT_" | sed -e 's/.*CVE-[0-9]//g' | cut -d: -f2 | sed -e 's/[[:blank:]]//g')
      if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
        print_output "$RED$EXPLOIT_$NC"
      elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
        print_output "$ORANGE$EXPLOIT_$NC"
      else
        print_output "$GREEN$EXPLOIT_$NC"
      fi
    done
    echo -e "\n[*] Exploit summary:" >> "$EXPLOIT_OVERVIEW_LOG"
    grep "Exploit\ available" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r >> "$EXPLOIT_OVERVIEW_LOG"
  fi
}

cve_db_lookup() {
  CVE_COUNTER_VERSION=0
  EXPLOIT_COUNTER_VERSION=0
  VERSION_SEARCH="${VERSION//\ /:}"
  VERSION_PATH="${VERSION//\ /_}"
  print_output ""
  print_output "[*] CVE database lookup with version information: ${GREEN}$VERSION_SEARCH${NC}"

  # CVE search:
  $PATH_CVE_SEARCH -p "$VERSION_SEARCH" > "$LOG_DIR"/aggregator/"$VERSION_PATH".txt

  # extract the CVE numbers and the CVSS values and sort it:
  readarray -t CVEs_OUTPUT < <(grep -A2 -e "[[:blank:]]:\ CVE-" "$LOG_DIR"/aggregator/"$VERSION_PATH".txt | grep -v "DATE" | grep -v "\-\-" | sed -e 's/^\ //' | sed ':a;N;$!ba;s/\nCVSS//g' | sed -e 's/: /\ :\ /g' | sort -k4 -V -r)

  for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
    ((CVE_COUNTER++))
    ((CVE_COUNTER_VERSION++))
    #extract the CVSS and CVE value (remove all spaces and tabs)
    CVSS_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f3 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
    CVE_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f2 | sed -e 's/\t//g' | sed -e 's/\ \+//g')

    EXPLOIT="No exploit available"

    # as we already know about a buch of kernel exploits - lets search them
    if [[ "$VERSION" == *kernel* ]]; then
      for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
        if [[ "$KERNEL_CVE_EXPLOIT" == "$CVE_VALUE" ]]; then
          EXPLOIT="Exploit available (Source: linux-exploit-suggester)"
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
        fi
      done
    fi

    if [[ "$CVE_SEARCHSPLOIT" -eq 1 ]] ; then
      # if no exploit was found lets talk to exploitdb:
      if [[ "$EXPLOIT" == "No exploit available" ]]; then
        mapfile -t EXPLOIT_AVAIL < <(cve_searchsploit "$CVE_VALUE" 2>/dev/null)
        if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
        #if cve_searchsploit "$CVE_VALUE" 2>/dev/null| grep -q "Exploit DB Id:" 2>/dev/null ; then
          EXPLOIT="Exploit available (Source: Exploit database)"
          echo -e "\\n[+] Exploit for $CVE_VALUE:\\n" >> "$LOG_DIR"/aggregator/exploit-details.txt
          for LINE in "${EXPLOIT_AVAIL[@]}"; do
            #cve_searchsploit "$CVE_VALUE" >> "$LOG_DIR"/aggregator/exploit-details.txt
            echo "$LINE" >> "$LOG_DIR"/aggregator/exploit-details.txt
          done
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
        fi
      fi
    fi

    CVE_OUTPUT=$(echo "$CVE_OUTPUT" | sed -e "s/^CVE/""$VERSION_SEARCH""/" | sed -e 's/\ \+/\t/g')
    BINARY=$(echo "$CVE_OUTPUT" | cut -d: -f1 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
    VERSION=$(echo "$CVE_OUTPUT" | cut -d: -f2- | sed -e 's/\t//g' | sed -e 's/\ \+//g' | sed -e 's/:CVE-[0-9].*//')
    # we do not deal with output formatting the usual way -> we use printf
    if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
      if [[ "$EXPLOIT" == *Source* ]]; then
        printf "${MAGENTA}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
      else
        printf "${RED}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
      fi
      ((HIGH_CVE_COUNTER++))
    elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
      if [[ "$EXPLOIT" == *Source* ]]; then
        printf "${MAGENTA}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
      else
        printf "${ORANGE}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
      fi
      ((MEDIUM_CVE_COUNTER++))
    else
      if [[ "$EXPLOIT" == *Source* ]]; then
        printf "${MAGENTA}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
      else
        printf "${GREEN}\t%-15.15s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
      fi
      ((LOW_CVE_COUNTER++))
    fi
  done

  { echo ""
    echo "[+] Statistics:$CVE_COUNTER_VERSION|$EXPLOIT_COUNTER_VERSION|$VERSION_SEARCH"
    echo "[+] Statistics1:$HIGH_CVE_COUNTER|$MEDIUM_CVE_COUNTER|$LOW_CVE_COUNTER"
  } >> "$LOG_DIR"/aggregator/"$VERSION_PATH".txt

  if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
    print_output ""
    print_output "[+] Found $RED$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $RED$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits in $ORANGE$VERSION_SEARCH.${NC}"
  elif [[ "$CVE_COUNTER_VERSION" -gt 0 ]];then
    print_output ""
    print_output "[+] Found $ORANGE$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $ORANGE$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits in $ORANGE$VERSION_SEARCH.${NC}"
  else
    print_output "[-] Found $CVE_COUNTER_VERSION CVEs and $EXPLOIT_COUNTER_VERSION exploits in $VERSION_SEARCH."
  fi
}

generate_cve_details() {
  sub_module_title "Collect CVE details."

  CVE_COUNTER=0
  EXPLOIT_COUNTER=0
  export MAX_PIDS=20 # for accessing the mongodb in threaded mode

  for VERSION in "${VERSIONS_CLEANED[@]}"; do
    # threading currently not working. This is work in progress
    if [[ "$THREADED" -eq "X" ]]; then
      cve_db_lookup &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup
    fi
  done

  if [[ "$THREADED" -eq "X" ]]; then
    wait_for_pid "${WAIT_PIDS_F19[@]}"
  fi

  print_output ""
  print_output "[*] Identified the following version details, vulnerabilities and exploits:"
  mapfile -t LOG_AGGR_FILES < <(find "$LOG_DIR"/aggregator/ -type f -name "*.txt" | sort 2> /dev/null)
  for FILE_AGGR in "${LOG_AGGR_FILES[@]}"; do
    if [[ -f $FILE_AGGR ]]; then
      BIN=""
      VERSION=""
      STATS=$(grep "\[+\]\ Statistics\:" "$FILE_AGGR" | cut -d: -f2- 2>/dev/null)
      #26|0|gnu:binutils:2.21:p12
  
      BIN_VERSION=$(echo "$STATS" | cut -d\| -f3-)
      # shellcheck disable=SC2001
      BIN_VERSION=$(echo "$BIN_VERSION" | sed -e 's/:/\ /g')
      #gnu:binutils:2.21:p12

      F_COUNTER=0
      for FIELD in $BIN_VERSION; do

        if [[ "$F_COUNTER" -eq 0 ]];then
          # the initial field is always the binary name
          BIN="$FIELD"
        elif echo "$FIELD" | grep -q "^p[0-9]"; then
          # something like "binary 1.23 p13"
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^r[0-9]"; then
          # something like "binary 1.23 r13"
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^b[0-9]"; then
          # something like "binary 1.23 b13"
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^sr[0-9][0-9][0-9][0-9]"; then
          #VxWorks:sr0530
          VERSION="$VERSION-$FIELD"
        elif echo "$FIELD" | grep -q "^[a-z]"; then
          # if FIELD starts with a letter it is a binary name
          # cases like r12 and p12 are already handled as versions
          BIN="$BIN $FIELD"
        elif echo "$FIELD" | grep -q "^[0-9]"; then
          VERSION="$VERSION $FIELD"
        elif [[ "$F_COUNTER" -gt 2 ]];then
          # if we reach this and our counter is above 2 it is probably a version field
          VERSION="$VERSION-$FIELD"
        fi
        # sometimes we start with a space
        # shellcheck disable=SC2001
        VERSION=$(echo "$VERSION" | sed -e 's/^\ //')
        # shellcheck disable=SC2001
        BIN=$(echo "$BIN" | sed -e 's/^\ //')
        (( F_COUNTER++ ))
      done
  
      EXPLOITS=$(echo "$STATS" | cut -d\| -f2 | sed -e 's/\ //g')
      CVEs=$(echo "$STATS" | cut -d\| -f1 | sed -e 's/\ //g')
  
      if [[ -n "$CVEs" && -n "$EXPLOITS" ]]; then
        if [[ "$CVEs" -gt 0 || "$EXPLOITS" -gt 0 ]]; then
          if [[ "$EXPLOITS" -gt 0 ]]; then
            printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
          else
            printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
          fi
        elif [[ "$CVEs" -eq 0 && "$EXPLOITS" -eq 0 ]]; then
          printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
        else
          # this should never happen ...
          printf "[+] Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
        fi
      fi
    fi
  done
  print_output "${NC}"
}

get_firmware_base_version_check() {
  sub_module_title "Collect version details of module r09 or s09 - firmware_base_version_check."
  if [[ -f "$LOG_DIR"/"$FW_VER_CHECK_LOG" ]]; then
    # if we have already kernel information:
    if [[ "$KERNELV" -eq 1 ]]; then
      readarray -t VERSIONS_STAT_CHECK < <(grep "Version information found" "$LOG_DIR"/"$FW_VER_CHECK_LOG" | cut -d\  -f5- | sed -e 's/ in firmware blob.//' | sort -u | grep -v "Linux kernel")
    else
      readarray -t VERSIONS_STAT_CHECK < <(grep "Version information found" "$LOG_DIR"/"$FW_VER_CHECK_LOG" | cut -d\  -f5- | sed -e 's/ in firmware blob.//' | sort -u)
    fi
  fi
}

get_version_vulnerability_check() {
  sub_module_title "Collect version details of module s30_version_vulnerability_check."
  print_output "[*] Currently nothing todo here ..."
}

get_kernel_check() {
  sub_module_title "Collect version details of module s25_kernel_check."
  if [[ -f "$LOG_DIR"/"$KERNEL_CHECK_LOG" ]]; then
    readarray -t KERNEL_CVE_EXPLOITS < <(grep "\[+\].*\[CVE-" "$LOG_DIR"/"$KERNEL_CHECK_LOG" | cut -d\[ -f3 | cut -d\] -f1 | sed -e 's/,/\r\n/g')
    ## do a bit of sed modifications to have the same output as from the pre checker
    readarray -t VERSIONS_KERNEL < <(grep "Statistics:" "$LOG_DIR"/"$KERNEL_CHECK_LOG" | sed -e 's/\[\*\]\ Statistics\:/kernel\ /' | sort -u)
  fi
}

get_usermode_emulator() {
  sub_module_title "Collect version details of module s115_usermode_emulator."
  if [[ -f "$LOG_DIR"/"$EMUL_LOG" ]]; then
    readarray -t VERSIONS_EMULATOR < <(grep "Version information found" "$LOG_DIR"/"$EMUL_LOG" | cut -d\  -f5- | sed -e 's/\ found\ in.*$//' | sed -e 's/vers..n\ //' | sed -e 's/\ (from.*$//' | sort -u)
  fi
}

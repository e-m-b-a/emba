FROM kalilinux/kali-rolling
# FROM kalilinux/kali-last-release

COPY ./installer.sh /
COPY ["./installer", "./helpers/helpers_emba_load_strict_settings.sh", "/installer/"]
COPY ./config/cve-database.db /installer/

WORKDIR /

# updates system
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo dialog apt curl git && \
    yes | sudo /installer.sh -s -D && \
    ulimit -c 0 && rm -rf /var/lib/apt/lists/*

WORKDIR /emba

# nosemgrep
ENTRYPOINT [ "/bin/bash" ]


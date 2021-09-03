FROM kalilinux/kali-rolling

ADD ./installer.sh /

WORKDIR /

# updates system, install EMBA, disable coredumps and final cleanup
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo dialog apt-utils && \
    yes | sudo /installer.sh -D && \
    ulimit -c 0 && rm -rf /var/lib/apt/lists/*

WORKDIR /emba

ENTRYPOINT [ "/bin/bash" ]


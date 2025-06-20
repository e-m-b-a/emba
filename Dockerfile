FROM kalilinux/kali-rolling

COPY ./installer.sh /

WORKDIR /

# docker build needs buildkit enabled
RUN --mount=type=bind,target=/installer,source=./installer \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo dialog apt curl git && \
    yes | /installer.sh -s -D && \
    ulimit -c 0 && rm -rf /var/lib/apt/lists/*

WORKDIR /emba

# nosemgrep
ENTRYPOINT [ "/bin/bash" ]


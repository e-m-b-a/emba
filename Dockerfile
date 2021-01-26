FROM kalilinux/kali-rolling

RUN apt-get update && \ 
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo build-essential liblzma-dev liblzo2-dev zlib1g-dev git && \
    git clone https://github.com/devttys0/sasquatch.git && \
    CFLAGS=-fcommon ./sasquatch/build.sh && \
    rm -r ./sasquatch

WORKDIR /app
ADD . /app

RUN yes | ./installer.sh

ENTRYPOINT [ "/bin/bash" ]

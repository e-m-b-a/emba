FROM kalilinux/kali-rolling

COPY ./installer.sh /
COPY ./installer /installer

WORKDIR /

# updates system
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install wget kmod procps sudo dialog apt-utils curl git

# install brew:
RUN useradd -m -s /bin/bash linuxbrew && \
    usermod -aG sudo linuxbrew &&  \
    mkdir -p /home/linuxbrew/.linuxbrew && \
    chown -R linuxbrew: /home/linuxbrew/.linuxbrew
USER linuxbrew
RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"

# install EMBA, disable coredumps and final cleanup
USER root
RUN yes | sudo /installer.sh -D && \
    ulimit -c 0 && rm -rf /var/lib/apt/lists/*

WORKDIR /emba

ENTRYPOINT [ "/bin/bash" ]


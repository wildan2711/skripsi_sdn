FROM iwaseyusuke/mininet

RUN \
  apt-get install -y software-properties-common python-software-properties
RUN add-apt-repository ppa:openjdk-r/ppa
RUN \
  apt-get update && \
  apt-get install -y openjdk-7-jre python-pip && \
  rm -rf /var/lib/apt/lists/*
RUN curl -sL https://deb.nodesource.com/setup_6.x | bash -
RUN apt-get install -y --no-install-recommends nodejs
RUN pip install ryu

# Define default command.
CMD ["bash"]
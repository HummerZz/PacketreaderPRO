FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app
RUN apt-get update && apt-get install -y \
   python3 python3-pip python3-venv \
   git build-essential cmake flex bison \
   libpcap-dev libpcre2-dev zlib1g-dev libssl-dev \
   pkg-config libhwloc-dev luajit libluajit-5.1-dev \
   libdumbnet-dev autotools-dev libtool liblzma-dev \
   iproute2 tcpdump curl ca-certificates \
&& rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/snort3/libdaq.git /tmp/libdaq \
&& cd /tmp/libdaq \
&& ./bootstrap \
&& ./configure \
&& make -j"$(nproc)" \
&& make install \
&& ldconfig
RUN git clone https://github.com/snort3/snort3.git /tmp/snort3 \
&& cd /tmp/snort3 \
&& ./configure_cmake.sh --prefix=/usr/local \
&& cd build \
&& make -j"$(nproc)" \
&& make install \
&& ldconfig
COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages -r /app/requirements.txt
COPY . /app
EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]

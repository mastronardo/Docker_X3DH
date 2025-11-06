# --- Builder image ---
FROM debian:trixie-slim AS builder
USER root
WORKDIR /app/lib
RUN apt update && apt upgrade -y && apt autoremove -y
RUN apt install -y curl git build-essential cmake libcurl4-openssl-dev libjansson-dev

# 1. Build and install libsodium
RUN curl -L -O https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz
RUN tar -xzf libsodium-1.0.20-stable.tar.gz
RUN rm -f libsodium-1.0.20-stable.tar.gz
WORKDIR /app/lib/libsodium-stable
RUN ./configure
RUN make && make check
RUN make install
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf
RUN ldconfig

# 2. Build and install libxeddsa
WORKDIR /app/lib
RUN git clone https://github.com/Syndace/libxeddsa.git
WORKDIR /app/lib/libxeddsa
RUN cmake -B build && cmake --build build
WORKDIR /app/lib/libxeddsa/build
RUN make install
RUN ldconfig

# 3. Copy and build our clients
WORKDIR /app
COPY . .
RUN make


# --- Alice Image ---
FROM debian:trixie-slim AS alice
WORKDIR /app
USER root

# Install only runtime dependencies
RUN apt update && apt upgrade -y && apt autoremove -y && apt install -y libcurl4 libjansson4

# Copy the runtime libraries we built from source
COPY --from=builder /usr/local/lib/libsodium.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/libxeddsa.so* /usr/local/lib/

# Copy the alice executable
COPY --from=builder /app/alice /app/alice

# Set up the linker
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig


# --- Bob Image ---
FROM debian:trixie-slim AS bob
WORKDIR /app
USER root

# Install only runtime dependencies
RUN apt update && apt upgrade -y && apt autoremove -y && apt install -y libcurl4 libjansson4

# Copy the runtime libraries we built from source
COPY --from=builder /usr/local/lib/libsodium.so* /usr/local/lib/
COPY --from=builder /usr/local/lib/libxeddsa.so* /usr/local/lib/

# Copy the bob executable
COPY --from=builder /app/bob /app/bob

# Set up the linker
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig
# BlkBox Honeypot - Docker Image
FROM denoland/deno:1.40.0

# Install Rust and build tools
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libsqlite3-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /opt/blkbox

# Copy Rust source and build
COPY Cargo.toml Cargo.lock ./
COPY lib_rust ./lib_rust
RUN cargo build --release

# Copy Deno source
COPY deno.json ./
COPY lib_deno ./lib_deno
COPY blkbox ./blkbox
COPY packages ./packages
COPY config.json ./
COPY main.ts ./

# Cache Deno dependencies
RUN deno cache main.ts

# Create data directory
RUN mkdir -p /data

# Expose ports
# Honeypots
EXPOSE 8080 2222 5432 3306 21
# Management dashboard
EXPOSE 9000
# C2 server
EXPOSE 8443

# Run BlkBox
CMD ["deno", "run", "--allow-all", "--unstable-ffi", "main.ts"]

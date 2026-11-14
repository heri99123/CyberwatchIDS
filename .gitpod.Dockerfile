FROM gitpod/workspace-full

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && echo 'source "$HOME/.cargo/env"' >> /home/gitpod/.bashrc

# Install system dependencies for rusqlite bundled + SSL
RUN sudo apt-get update && sudo apt-get install -y \
    pkg-config \
    libssl-dev \
    build-essential \
    && sudo rm -rf /var/lib/apt/lists/*

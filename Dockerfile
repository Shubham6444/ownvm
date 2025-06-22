FROM ubuntu:22.04

# Install packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    nginx \
    nodejs \
    npm \
    curl \
    wget \
    git \
    vim \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# Create user and set password
RUN useradd -m -s /bin/bash devuser && \
    echo 'devuser:ubuntupass' | chpasswd && \
    usermod -aG sudo devuser && \
    echo 'devuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/devuser && \
    chmod 0440 /etc/sudoers.d/devuser

# Add Nginx welcome page
RUN echo '<h1>Welcome to your VM!</h1><p>Container is running!</p>' > /var/www/html/index.html

# Expose ports
EXPOSE 22 80

# Start services
CMD service ssh start && service nginx start && tail -f /dev/null

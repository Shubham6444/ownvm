FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    nginx \
    nodejs \
    npm \
    systemd \
    curl \
    wget \
    git \
    vim \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create devuser
RUN useradd -m -s /bin/bash devuser
RUN usermod -aG sudo devuser
RUN echo 'devuser ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Configure Nginx
RUN echo '<h1>Welcome to your VM!</h1><p>Your container is running successfully!</p>' > /var/www/html/index.html

# Expose ports
EXPOSE 22 80

# Start services
CMD service ssh start && service nginx start && tail -f /dev/null

# Use an official Ubuntu base image
FROM ubuntu:latest

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install build essentials (GCC, Make, etc.) and other dependencies
RUN apt-get update && \
    apt-get install -y build-essential libc6-dev clang libelf-dev linux-headers-$(uname -r) && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory in the Docker container
WORKDIR /usr/src/app

# Copy the entire project into the container
COPY . .

# By default, run make all to build the project
CMD ["make", "all"]


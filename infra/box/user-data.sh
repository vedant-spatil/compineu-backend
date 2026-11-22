#!/bin/bash
# EC2 user data for a box launched by hand in the console ("Advanced details" -> "User data" -> Choose file).
# This is the same first-boot script that infra/compineu.yaml embeds, so keep the two in step. The stack uses it
# automatically; you only need this file when you do not deploy the stack.
# First boot only. Ubuntu 24.04 ships the SSM agent (snap), so Session Manager works without SSH once the instance has
# an IAM instance profile with AmazonSSMManagedInstanceCore.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
apt-get update -y
apt-get install -y ca-certificates curl git jq unzip
command -v docker || curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
systemctl enable --now docker
snap install aws-cli --classic || true
mkdir -p /opt/compineu && chown ubuntu:ubuntu /opt/compineu
echo ready > /opt/compineu/.bootstrapped

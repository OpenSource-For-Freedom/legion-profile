# Runs a QEMU virtual machine inside a container, so the VM tests need only
# Docker and /dev/kvm on the host, not QEMU itself.
FROM ubuntu:26.04
RUN apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    qemu-system-x86 qemu-utils cloud-image-utils openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*

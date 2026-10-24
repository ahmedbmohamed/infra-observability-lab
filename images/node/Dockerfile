# A small Ubuntu server reachable over SSH, used in place of a VM.
# It has no systemd, so supervisord starts the services (sshd here, nginx and exporters added by Ansible).
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       openssh-server python3 sudo supervisor ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /etc/supervisor/conf.d

# Packages must not start services themselves: supervisord does (or nginx would start twice).
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d

# Ansible logs in as "ops" with an SSH key and uses sudo.
RUN useradd --create-home --shell /bin/bash ops \
    && echo "ops ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ops \
    && chmod 0440 /etc/sudoers.d/ops

COPY supervisord.conf /etc/supervisor/supervisord.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

EXPOSE 22 443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

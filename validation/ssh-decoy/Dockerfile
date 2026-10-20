FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client sshpass nmap hydra netcat-openbsd && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir paramiko
RUN useradd --uid 10001 --create-home lab
COPY --chmod=644 ssh_config /etc/ssh/ssh_config.d/99-decoy-lab.conf
USER 10001:10001
WORKDIR /tmp
CMD ["sleep", "infinity"]

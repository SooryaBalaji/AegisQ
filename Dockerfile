# AegisQ runtime image. Ubuntu 26.04 ships OpenSSL 3.5, OpenSSH 10 and a curl built on OpenSSL 3.5,
# so the openssl / openssh backends and the curl benchmark work out of the box.
FROM ubuntu:26.04 AS base
ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates openssl openssh-client curl git \
 && rm -rf /var/lib/apt/lists/*

FROM base AS build
COPY pyproject.toml README.md /src/
COPY src /src/src
ARG EXTRAS=agent
RUN python3 -m venv /opt/aegisq \
 && /opt/aegisq/bin/pip install --upgrade pip \
 && /opt/aegisq/bin/pip install "/src[${EXTRAS}]"

# Demo / Docker Desktop image: adds the docker CLI so the agent can run `nginx -t` and reloads in the demo
# containers through the mounted Docker socket. Runs as root because the socket is root-owned.
# Used by demo/docker-compose.yml; build it alone with `docker build --target demo -t aegisq:demo .`.
FROM base AS demo
COPY --from=build /opt/aegisq /opt/aegisq
COPY --from=docker:cli /usr/local/bin/docker /usr/local/bin/docker
ENV PATH=/opt/aegisq/bin:$PATH AEGISQ_HOME=/var/lib/aegisq/workspace
WORKDIR /demo
ENTRYPOINT ["aegisq"]
CMD ["--help"]

# Test image: the full test suite, runnable on any OS with Docker (Windows included).
FROM demo AS test
COPY pyproject.toml README.md /src/
COPY src /src/src
COPY tests /src/tests
COPY aegisq.example.yaml /src/
RUN /opt/aegisq/bin/pip install -e "/src[dev,agent,quantum]"
WORKDIR /src
ENTRYPOINT ["python3", "-m", "pytest"]
CMD []

# Default runtime image: non-root, no docker CLI.
FROM base AS runtime
COPY --from=build /opt/aegisq /opt/aegisq
RUN useradd --system --create-home --home-dir /var/lib/aegisq --shell /usr/sbin/nologin aegisq
ENV PATH=/opt/aegisq/bin:$PATH AEGISQ_HOME=/var/lib/aegisq/workspace
USER aegisq
WORKDIR /var/lib/aegisq
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD ["python3", "-c", "import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"]
ENTRYPOINT ["aegisq"]
CMD ["--help"]

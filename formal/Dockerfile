ARG BASE_IMAGE
FROM ${BASE_IMAGE}

# BASE_IMAGE must be a Debian/Ubuntu-family JRE digest (e.g. eclipse-temurin:21-jre)
# because this Dockerfile installs dependencies with apt-get and verifies the
# tlac2 jar with sha256sum. Alpine/distroless bases require a separate Dockerfile.

ARG TLA2TOOLS_VERSION=1.8.0
ARG TLA2TOOLS_SHA256

RUN test -n "${TLA2TOOLS_SHA256}" \
    && apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --location --silent --show-error \
        "https://github.com/tlaplus/tlaplus/releases/download/v${TLA2TOOLS_VERSION}/tla2tools.jar" \
        --output /opt/tla2tools.jar \
    && echo "${TLA2TOOLS_SHA256}  /opt/tla2tools.jar" | sha256sum --check

WORKDIR /spec
ENTRYPOINT ["java", "-cp", "/opt/tla2tools.jar", "tlc2.TLC"]

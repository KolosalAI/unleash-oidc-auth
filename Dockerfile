# Unleash with OIDC (Zitadel) login for the admin UI. Single stage on purpose: the base image has no npm and
# server.mjs needs no dependencies, so building never touches a package registry.
# unleash-server is AGPL-3.0-or-later; this repository is the complete source of our changes (see README.md).
ARG UNLEASH_IMAGE_VERSION
FROM unleashorg/unleash-server:${UNLEASH_IMAGE_VERSION}

# Git commit of this repository the image was built from (see README.md: source offer).
ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/KolosalAI/unleash-oidc-auth" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.description="unleash-server with OIDC (Zitadel) login for the admin UI (custom auth hook)"

COPY --chown=node:node server.mjs /unleash/server.mjs

# WORKDIR /unleash and USER node are inherited from the base image.
CMD ["node", "server.mjs"]

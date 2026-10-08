FROM python:3.12-slim
RUN pip install --no-cache-dir uv
WORKDIR /app

# Pin the garmin_mcp worker to a reviewed commit (override at build time).
# Bumping this is a deliberate, reviewed action: the worker runs with each
# user's decrypted Garmin tokens, so a floating ref would run unreviewed code.
#
# Source: robcasselman/garmin_mcp, which is Taxuspt/garmin_mcp at 2974244 plus
# one fix (FIT records carry altitude, speed and distance from the enhanced_*
# fields modern devices write; upstream dropped them). Upstream PR: https://github.com/Taxuspt/garmin_mcp/pull/383
# Point GARMIN_MCP_REPO back at Taxuspt once that fix is in an upstream commit.
ARG GARMIN_MCP_REPO=https://github.com/robcasselman/garmin_mcp
ARG GARMIN_MCP_REF=01b248a96af85f004d61eda78f52a8a6357a986b
ENV GARMIN_MCP_REF=${GARMIN_MCP_REF}

# git: uv installs the pinned garmin_mcp worker from a git ref.
# tini: reaps the many worker subprocesses the gateway spawns.
RUN apt-get update && apt-get install -y --no-install-recommends git tini && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY scripts ./scripts
# mcp<2: garmin_mcp is written against the mcp 1.x API (mcp.server.fastmcp) and
# doesn't bound its own dependency — mcp 2.0.0 (2026-07-28) removed that module,
# and the first image rebuild after the release crashed every worker spawn with
# ModuleNotFoundError (2026-07-31 incident). The worker's other deps float too;
# pin here, in the same resolve, whenever one of them breaks the same way.
RUN uv pip install --system . && \
    uv pip install --system "garmin-mcp @ git+${GARMIN_MCP_REPO}@${GARMIN_MCP_REF}" "mcp<2"
ENTRYPOINT ["tini", "--"]
CMD ["missingmcp"]
EXPOSE 8080
# No VOLUME directive: Railway's builder rejects it ("use Railway Volumes") and
# provides /data via a platform-managed volume; self-hosters mount /data with
# `docker run -v`. Persistence is supplied by the runtime, not the image.

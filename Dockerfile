# Root Justice / Artex Antidote edge shield — defensive, log-only by default.
#
# The container runs `root-justice serve` with NO --enforce flag, so virtual
# patching stays log-only (design §4.4): every request still gets a normal
# response, nothing is denied, and events are only recorded for review. It
# never reaches out to any attacker address.
FROM python:3.13-slim

# No bytecode writes, unbuffered stdout for container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the package itself (standard-library only — no third-party runtime
# deps, so this stays fast and offline-friendly).
COPY pyproject.toml README.md ./
COPY artex_antidote ./artex_antidote
RUN pip install --no-cache-dir .

# Evidence ledger lives here; mount a volume over it (see docker-compose.yml).
# Create it up front and hand ownership to the non-root user.
RUN useradd --create-home --uid 10001 rootjustice \
    && mkdir -p /app/evidence_out \
    && chown -R rootjustice:rootjustice /app

# Drop privileges — the shield never needs root.
USER rootjustice

EXPOSE 8080

# Liveness/readiness: a simple TCP-level check that the listener is up. The
# richer JSON probes live in artex_antidote.health for an orchestrator to call.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(('127.0.0.1',8080))==0 else 1)"

# Log-only by default (no --enforce).
#
# The process binds 0.0.0.0 INSIDE the container. This is required: Docker's
# port forwarding cannot reach a process that listens only on the container's
# loopback, so the listener must accept the bridge interface. This is NOT the
# same as the host-level "loopback by default" story in the README — exposure to
# the network is controlled at publish time, not here.
#
# IMPORTANT for operators:
#   * docker-compose.yml publishes this port on the HOST loopback (127.0.0.1)
#     only, so an out-of-the-box `docker compose up` is not reachable off-box.
#   * If you publish it more widely, put the shield behind your own TLS
#     terminator / reverse proxy, and do NOT expose GET /dashboard — it is
#     unauthenticated and meant to be reached over loopback only.
CMD ["root-justice", "serve", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--evidence", "/app/evidence_out/evidence_ledger.jsonl"]

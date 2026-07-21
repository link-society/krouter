# Performance

## Data-plane requirements

Each data-plane pod MUST:

- Sustain at least 10,000 simultaneous established downstream connections.
- Preserve those connections across Route/Gateway configuration reloads.
- Avoid unexpected proxy-generated disconnects or errors during the
  concurrency test.
- Exhibit bounded memory use with no sustained growth after connections
  close and configuration generations are reclaimed.
- Use multiple available CPUs effectively.

The 10,000-connection requirement is a release gate.

## Comparative benchmarks

A reproducible benchmark suite MUST compare krouter, NGINX, and Traefik on
identical hardware, Kubernetes networking, TLS settings, backend, request
mix, and connection counts. It reports:

- Successful requests per second.
- p50, p95, and p99 latency.
- Error and disconnect rate.
- CPU consumption.
- Peak and steady-state memory.
- Time and errors during configuration reload.

Comparative benchmark results are published for the POC; a precise parity
threshold is set only after the common harness establishes stable
baselines.

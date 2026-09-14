# Network observation and scoped DNS evidence

Status: accepted

The MVP records TCP and UDP connection attempts for IPv4 and IPv6 destinations.
On Linux, observation-only `cgroup/connect4` and `cgroup/connect6` programs emit
a strict 72-byte record containing process identity, monotonic timestamp,
protocol, destination address, and port. The hook returns allow and does not
load or apply policy. The daemon supplies the run ID and performs correlation;
the kernel must not infer a hostname from an address.

DNS evidence is keyed by the Sentry run and destination address, records the
resolver and its provenance, and expires at the observed answer expiry. A
connection is labelled with a domain only when unexpired evidence exists for
that same run; every other connection is `UnknownDestination`.

The cache has a fixed capacity. New evidence is rejected once it is full of
unexpired entries, rather than evicting evidence that could explain a later
connection. A capacity rejection is observable diagnostic evidence and must
not be interpreted as a permit decision.

DNS-to-connect is attribution evidence, not proof of the remote service. Shared
IP addresses can serve unrelated domains. Encrypted DNS may prevent the sensor
from seeing a resolver answer, proxy connections identify the proxy rather than
the final service, and DNS resolved outside the observed run is intentionally
not correlated. These cases remain `UnknownDestination` unless other supported
evidence is added later.

The native arm64 runtime fixture covers TCP and UDP over IPv4 and IPv6 and
requires all four direct loopback attempts to remain `UnknownDestination` when
the DNS cache is empty. Live DNS response parsing and attribution are still
open. Until a sensor records an answer, `DnsObservation` is unavailable and a
domain-based policy cannot activate. The cgroup hook observes connection
attempts, including attempts made through sockets created before attachment;
it does not observe established traffic that performs no new connect.

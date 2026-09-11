# Network observation and scoped DNS evidence

Status: accepted

The MVP records TCP and UDP connection attempts for IPv4 and IPv6 destinations.
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

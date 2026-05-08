# Tests

This folder is for black-box and integration tests that exercise VeilGate through
exported APIs.

Package-private unit tests stay next to their packages under `internal/` because
they intentionally verify unexported detector, TLS fingerprint, tarpit, and ML
helpers. Moving those tests here would either break them or force production code
to expose internals just for tests.

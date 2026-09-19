# Primary Diagram
The diagram below illustrates the primary's architecture and could be useful to keep in mind while going through the code.

<p align="center">
  <img src="https://github.com/asonnino/narwhal/blob/master/.assets/diagram-primary.svg">
</p>

### Cross-group delay experiment

During the configured attack window, enabled message types are sent to every peer.
Same-group delivery has no added delay; cross-group delivery is scheduled after
`attack_cross_group_delay_ms` (default `500`, in milliseconds; `0` means no added delay).
This replaces the previous coverage-based broadcast/sync filtering. The delay is
independent of `reference`, `coverage`, and `kappa`.

`attack_limit_headers` selects header broadcasts; `attack_limit_certificates`
selects certificate broadcasts and certificate synchronization replies. Sync replies
use the group of the replying node, not the certificate author. Votes are unchanged.
Timers run asynchronously, and messages scheduled during the attack are still sent
after their timers expire even if the attack window has ended. The configured delay
is additional sender-side waiting time, not an exact bound on receiver acceptance or
consensus latency. Multiple cross-group hops can each incur the delay.

For CloudLab Fabric runs, pass `--attack-cross-group-delay-ms=500` to
`fab cloudlab-remote`. The standalone `run_cloudlab_benchmark.py` accepts the same
option. The value is recorded in committee configuration and run metadata.

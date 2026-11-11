---
tags: [balancer, country, google-gate]
---
Exit country is observed, never inferred; unknown is never a failure.

The balancer stores the country Cloudflare reports for an exit (`cdn-cgi/trace`, `loc=XX`) in `nodes.country`, because provider remarks are unreliable (most feed remarks are hash-style). Rules that must survive future edits: an unreadable or `XX` trace is stored as unknown with a fresh `country_checked` stamp and MUST NOT quarantine the node; `--require-country CC` is opt-in and, when no candidate matches, rotation keeps the current node instead of switching country; selection order is `uses` then `delay_ms` with no per-cause weighting. Details: `scripts/DECISIONS.md`.
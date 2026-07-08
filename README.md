# THE CHAIN — the corpus, tethered

The whole ROOT0 corpus, in one **append-only SHA-256 hash-chain**. Every repo
carries a `.dlw` seal; those seals are linked — `link[i] = sha256(index|slug|seal|prev)`,
a **genesis** derived from an anchor string, a **head** that commits to everything.

This page **ships the control arm client-side**: a from-scratch, pure-JS SHA-256
(byte-for-byte identical to Python's `hashlib`, verified in Node) recomputes the
genesis from the anchor and the head from every seal — **zero network** — so you
verify the corpus's provenance yourself. Then **tamper any seal** and watch the
chain diverge from that link onward and the head stop matching: tamper-evident,
in front of you.

## What it proves (green) — and doesn't (amber)

- **GREEN, verified here:** genesis is recomputed from the anchor (not asserted);
  the head is recomputed by chaining all seals; changing any seal breaks the chain
  from that link on. Append-only: a new sphere adds one link at the tip, every
  earlier link unchanged.
- **AMBER, not claimed:** it attests the seals *as inlined, in this order*. It does
  not independently prove each seal still matches its repo's live content — that is
  the repo's own `<slug>.dlw/.attribute` and `.chain` tether. A seal is a
  provenance marker, not a claim about quality. The chain proves **integrity and
  order, not merit.**

## Reproduce

```
python ../\_dlw_chain.py --verify   # recompute the ledger from stored seals
python build.py                     # regenerate index.html from ../dlw-chain.json
```

The ledger (`dlw-chain.json`) is written by `_dlw_chain.py`; this page is generated
by `build.py`. Kin: the sealing machinery — THE SEALING BENCH (mints one seal),
THE ANCHOR, THE REPLAY.

---
David Lee Wise / ROOT0 / TriPod LLC · CC-BY-ND-4.0

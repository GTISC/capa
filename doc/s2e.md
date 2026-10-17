# Mal-S2E dynamic traces

The GTISC fork can match capa dynamic rules against Mal-S2E's
`api-lifecycle.jsonl` journal:

```console
uv run python scripts/analyze-s2e.py /path/to/s2e-out-0 \
  --rules /path/to/capa-rules \
  --out s2e-capa.json
```

The extractor validates paired lifecycle entries and returns, exposes only
successful calls, and keeps every `(instance, pid, lifetime, state)` stream
separate. Divergent symbolic states therefore cannot satisfy one rule by
combining features from different paths. API names, selected concrete string
arguments, and selected nonzero integer arguments become capa call features.

The output calls ATT&CK tags **candidates**. A dynamic rule match is useful for
prioritizing deeper exploration, but it does not establish adversary intent or
technique completion. Mal-S2E separately checks original-sample identity,
byte-level caller provenance, and technique-specific OS-effect contracts
before promoting a candidate to qualified runtime evidence.

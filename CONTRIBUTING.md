# Contributing

```
git clone https://github.com/rchandnaWUSTL/stopcord && cd stopcord
uv sync
uv run pytest
uv run stopcord demo
```

A few rules the project holds to:

- Nothing in the evidence path calls a model. That covers policy decisions, the log, `verify`, `replay`, `report` and the console. A model-based check can be added later only if it's labeled advisory.
- `decide()` stays pure: no I/O, no randomness. Anything that touches the filesystem happens in normalization, before it.
- Don't change the log format in a way that stops existing logs from verifying.
- New behavior comes with a test.

Open an issue before a large change.

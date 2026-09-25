# GTISC capa and rules

This fork tracks `mandiant/capa` on `master`. Its `rules` submodule points to
[`GTISC/capa-rules`](https://github.com/GTISC/capa-rules), which tracks the
upstream rules and adds reviewed GTISC rules under `in-house/`. Clone with
`git clone --recurse-submodules https://github.com/GTISC/capa.git` or run
`git submodule update --init --recursive` in an existing checkout.

The current upstream published release for both repositories is v9.4.0.
`master` can move ahead of that release; use a fixed commit in an experiment
manifest. The `rules` gitlink fixes the exact companion rule revision for this
fork. For repeatable v9.4.0-era runs already in Mal-S2E, the project also keeps
an unmodified upstream v9.4.0 snapshot and an independent in-house overlay.

The GTISC rule documentation is in `rules/in-house/README.md`. capa discovers
the whole `rules/` directory by default in a recursive source checkout. When
running a pip-installed capa, pass `-r /path/to/GTISC/capa-rules` explicitly;
pip packages do not bundle the repository's rules or signatures.

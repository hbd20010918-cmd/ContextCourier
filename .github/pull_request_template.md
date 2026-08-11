## Problem and outcome

<!-- Explain the handoff problem and the observable result. -->

## Safety and compatibility

- [ ] No real or contiguous scanner-recognizable credential is present.
- [ ] User configuration cannot bypass an immutable safety rule.
- [ ] `inspect` still distinguishes itself from verified integrity.
- [ ] Schema v1 compatibility is preserved or the format change is explicitly documented.
- [ ] Account/chat migration boundaries remain accurate.

## Verification

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m compileall -q src`
- [ ] Package build/install smoke test
- [ ] Relevant documentation and changelog updated

# Contributing to meshfind

Thanks for your interest! Bug reports, test cases, documentation fixes and hardware results are all welcome.

## Ground rules

- **Keep it honest.** Results in the README are either measured here or clearly marked as simulated.
  Please do the same in PRs: say how you measured something, and never fill a hardware table from a simulation.
- **Tests first.** Every behaviour change needs a test. Run the fast suite before opening a PR:
  ```bash
  python -m pytest -q && python tools/host_test.py
  ```
- **Small PRs.** One logical change per PR, with a clear description.
- **Style.** Follow the existing code style and `.editorconfig` (4-space indent, LF line endings, no trailing whitespace).
- **Protocol changes** must update `docs/PROTOCOL.md`, regenerate `vectors/meshfind_vectors.json` (`python -m meshfind vectors`) and keep the C core byte-identical to Python.

## Reporting bugs and ideas

Use the issue templates (bug report / feature request). For security problems, **do not open a public
issue**: see [SECURITY.md](SECURITY.md).

## Figures

The README images are generated from the code by `docs/assets/make_figures.py`. If your change alters
the results, regenerate them and commit the updated images with the script output.

## License

By contributing you agree that your contributions are licensed under the MIT License of this repository.

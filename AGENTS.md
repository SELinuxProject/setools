# Project Guidelines

## Project Overview

SETools is a Python 3.10+ SELinux policy-analysis library and tool suite. It includes Python APIs,
command-line tools, a PyQt GUI, a FastMCP server, and a Cython extension linked against libselinux
and libsepol.

## Repository Layout

- `setools/` contains the public Python library and policy query modules.
- `setools/checker/` contains the policy checker framework and built-in checks.
- `setools/diff/` contains policy comparison implementations.
- `setools/mcp/` contains the FastMCP server, configuration, session management, and result
  encoding.
- `setools/policyrep.pyx` and `setools/policyrep/` contain the Cython policy-representation layer.
  Treat `setools/policyrep.c` as generated output; make source changes in the `.pyx` and `.pxi`
  files.
- `setoolsgui/` contains the PyQt GUI.
- `man/` contains the command-line tool man pages and their translations.
- `docs/` contains project documentation and example configurations.
- The root scripts (`seinfo`, `sesearch`, `sediff`, `sedta`, `seinfoflow`, `sechecker`, `apol`, and
  `setools-mcp`) are installed command-line entry points.
- `tests/library/` mirrors the public library and includes dedicated tests for `checker`, `mcp`, and
  `policyrep`; `tests/gui/` covers the PyQt GUI. Keep new tests near the subsystem they cover and
  reuse the policy fixtures in those directories.

## Documentation

- Use the [SELinux Notebook](https://github.com/SELinuxProject/selinux-notebook/tree/main/src) as
  the most authoritative reference for general SELinux concepts, behavior, policy languages, object
  classes and permissions, tools, and configuration.
- If the SELinux Notebook does not answer the question, consult the upstream SELinux userspace
  man pages under `https://github.com/SELinuxProject/selinux/*/man/**` for further information.
- Format Markdown documentation with a maximum line length of 100 columns. Preformatted code
  blocks and Markdown tables may exceed this limit.
- Align Markdown table cells and delimiters so tables are readable in the source text.
- Use spaces for indentation in Markdown documentation; do not use tabs.
- When a code change affects documented behavior or configuration, update the applicable man pages,
  project documentation, and example configurations in the same change. Cross-check all three for
  consistent option names, defaults, behavior, and examples.
- Name project documentation files with an uppercase basename and lowercase `.md` extension, for
  example `CONFIGURATION.md`.
- Every command-line tool must have a corresponding man page under `man/`. When adding or changing
  a tool, create or update its man page in the same change so options, defaults, and behavior match.

## Code Conventions

- Endeavor to use idiomatic Python and follow the existing code conventions demonstrated by the
  surrounding implementation. Preserve public APIs unless a change explicitly requires an update.
- All class definitions, functions, and methods should have a docstring, except magic methods.
- When changing public API behavior, add compatibility code to preserve previous access when
  possible and emit a `DeprecationWarning` from the deprecated path.
- Use type annotations for new Python code and keep it compatible with the mypy settings in
  `pyproject.toml`.
- Keep lines at or below 100 characters, as configured in `tox.ini`.
- Prefer existing query mixins, descriptors, and policy-representation abstractions over adding
  parallel implementations.
- Keep changes narrowly scoped. Do not reformat unrelated code or modify generated/build output.
- When a lint exemption is necessary, apply it at the narrowest reasonable scope rather than
  weakening lint checks broadly.
- Every code change must include a corresponding unit test change. Ensure all new and modified code
  paths are covered by unit tests.
- When a majority of a dictionary's keys are known in advance and used in the code, define an enum
  for the keys and use its members at every access site. Use named constants or enum members for
  repeated domain-specific values; do not repeat magic string or numeric literals.
- Do not add a dependency without user confirmation. First, compare an implementation using the
  standard library and existing dependencies with the proposed dependency. Summarize the tradeoffs
  in implementation complexity, features, and maintenance. Also report the proposed dependency's
  transitive dependency cost and availability in supported Fedora and Ubuntu releases, then ask for
  approval before changing dependency metadata.

## Build and Test

The extension requires the libselinux and libsepol development headers and libraries. Build it in
place before running tests directly:

```bash
python setup.py build_ext -i
python -m pytest tests
```

Use tox for the standard project checks:

```bash
tox -e python3                      # unit tests
tox -e mypy                         # type checking
tox -e lint                         # pylint errors
tox -e pep8                         # pycodestyle
tox -p -e python3,mypy,lint,pep8
```

During development, run the narrowest relevant test first, for example:

```bash
tox -e python3 -- tests/library/test_typequery.py
```

Set `USERSPACE_SRC` when building against a local SELinux userspace tree. The tox environments
pass this variable through. Graph-analysis tests may also require NetworkX and pygraphviz, while GUI
tests require PyQt6 and pytest-qt.

## MCP Security

- Review every MCP server change for session security.
- Keep session-owned state, caches, inputs, and results isolated. One session must not be able to
  observe, mutate, evict, or otherwise interfere with another session's data.
- Add unit tests using at least two independent sessions to verify that state and data cannot leak
  between them, including under concurrent access when the changed code supports concurrency.

## Evidence and Uncertainty

- Inspect the relevant current code before answering questions or making changes.
- Read the applicable specifications and authoritative documentation; do not infer requirements
  from code alone when a specification governs the behavior.
- Fetch web references directly from their authoritative source. Do not rely on cached web search
  results, summaries, or snippets.
- Do not make unsupported assumptions or speculate when evidence is unavailable. If the code and
  authoritative references do not determine the answer, or if they conflict, state the uncertainty
  and ask the user a clarifying question before proceeding.

## Change Discipline

- Do not commit local policy binaries, analysis output, build directories, or compiled extension
  artifacts unless the task explicitly calls for a tracked fixture or generated release artifact.
- Update `README.md`, command help, or man pages when user-visible behavior changes.
- Report the focused checks run and any checks that could not run because native or GUI dependencies
  are unavailable.
- Keep each commit to one logical change and ensure the tree builds after each commit.
- Include a `Signed-off-by` line using the contributor's real name in every commit.
- Submit changes through a GitHub pull request.

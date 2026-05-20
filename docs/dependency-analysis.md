# Dependency Analysis

GuardChain parses dependency declarations from `requirements.txt`, `pyproject.toml`, `setup.cfg`, `setup.py` keyword arguments, `METADATA`, and `PKG-INFO`.

It uses `packaging.requirements.Requirement` when possible to parse names, extras, markers, direct URLs, and version specifiers. A fallback parser handles VCS and local-path requirements.

Detected dependency risks include:

- Direct URL dependencies.
- VCS dependencies.
- Local path dependencies.
- Unpinned dependencies.
- Typosquatting against `guardchain/data/popular_packages.txt`.
- Imported but not declared dependencies.
- Declared but not imported dependencies.
- Local educational suspicious dependency list matches.

The local suspicious package list is demo data, not a complete malware intelligence feed.

## Import Mapping

GuardChain normalizes distribution names and import names before comparing declared dependencies with imports. It also includes a small mapping file at `guardchain/data/import_name_map.yaml` for common differences such as `PyYAML -> yaml`, `Pillow -> PIL`, `scikit-learn -> sklearn`, `beautifulsoup4 -> bs4`, `opencv-python -> cv2`, and `python-dateutil -> dateutil`.

Python standard library imports use `sys.stdlib_module_names` when available, with a small fallback list for older runtimes.

## Optional Dependency Closure

The default scan is offline and does not resolve dependency graphs. Dependency closure requires:

```bash
python -m guardchain scan \
  --path ./samples/divide_and_hide/root_pkg \
  --resolve-deps \
  --dependency-no-index \
  --dependency-find-links ./samples/divide_and_hide/dist
```

When enabled, GuardChain:

- uses declared requirement strings extracted by `dependency_analyzer.py`;
- runs `python -m pip install --dry-run --ignore-installed --report - --quiet`;
- adds `--only-binary=:all:` by default so packages without wheels are unresolved rather than built from sdist;
- applies a timeout and package-count limit;
- supports local fixture/package indexes through `--dependency-no-index` and `--dependency-find-links`;
- records resolver/download failures as warnings so the scan can still complete;
- downloads resolved wheel/zip artifacts and scans them statically with reduced limits;
- annotates dependency-origin findings with dependency package, version, and chain context.

Reports include dependency graph data and dependency risk paths when dependency-origin findings are present.

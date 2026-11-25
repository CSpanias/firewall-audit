# Installation

Firewall-Audit requires Python 3.10 or later.

## Install with uv

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then run:

```powershell
uv tool install git+https://github.com/CSpanias/firewall-audit
firewall-audit --help
```

Update the installed tool with:

```powershell
uv tool upgrade firewall-audit
```

## Install from a clone

```powershell
git clone https://github.com/CSpanias/firewall-audit
Set-Location firewall-audit
python -m pip install .
firewall-audit --help
```

For development, install the docs extra and run the test suite:

```powershell
python -m pip install -e ".[docs]"
python -m unittest discover -s tests
python -m mkdocs build --strict
```

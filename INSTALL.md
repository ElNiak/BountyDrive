# Installation

## Package

```bash
# For reCAPTCHA
sudo apt-get install portaudio19-dev

```

## Pre-Commit

```bash
python3 -m pip install pre-commit
pre-commit installed at .git/hooks/pre-commit
```

## Classical

```bash
sudo apt-get install python3 python3-dev python3-venv
python3 --version
# Python 3.10.12
```

```bash
python3 -m venv python3-venv
source python3-venv/bin/activate
python3 -m pip install -U pip wheel
python3 -m pip install -r requirements.txt
```

Update `config.ini`

Run with `python3 bounty_drive.py`

## PyPy 

Not ready - SEGFAULT in some libs (urllib3, cryptography downgraded).

Install PyPy from [here](https://doc.pypy.org/en/latest/install.html)

Package compatible with PyPy are in `requirements_pypy.txt`
* http://packages.pypy.org/
* https://doc.pypy.org/en/latest/cpython_differences.html

```bash
sudo apt-get install pypy3 pypy3-dev pypy3-venv
pypy3 --version
# Python 3.9.19 (7.3.16+dfsg-2~ppa1~ubuntu20.04, Apr 26 2024, 13:32:24)
# [PyPy 7.3.16 with GCC 9.4.0]
```

```bash
pypy3 -m venv pypy3-venv
source pypy3-venv/bin/activate
pypy3 -m pip install -U pip wheel
pypy3 -m pip install -r requirements_pypy.txt
```

pdate `config.ini`

Run with `pypy3 bounty_drive.py`
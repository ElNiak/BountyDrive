# Makefile

# Variables
VENV := venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip3

# Default target
all: setup

# Setup the virtual environment and install requirements
setup: $(VENV)/bin/activate
	$(PYTHON) -m pip install wheel
	$(PYTHON) -m pip install -r requirements.txt

# Create virtual environment
$(VENV)/bin/activate:
	python3 -m venv $(VENV)

# Clean up the environment
clean:
	rm -rf $(VENV)

# Note: Use 'source venv/bin/activate' to activate the virtual environment manually.

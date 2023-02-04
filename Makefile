# Define variables
PYTHON = python
FILENAME = sftptester.py
TESTFILE = test.py
# Define targets
lint:
	pylint $(FILENAME) || true
typecheck:
	mypy $(FILENAME) || true
style:
	flake8 $(FILENAME) || true
format:
	black -v $(FILENAME) || true
test:
	$(PYTHON) -m pytest -xv $(TESTFILE) || true

all: lint typecheck style format test
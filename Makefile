ROOT = $(shell echo "$$PWD")
COVERAGE = $(ROOT)/build/coverage
PACKAGE = edx_rest_framework_extensions

clean:
	find . -name '*.pyc' -delete
	coverage erase
	rm -rf build

quality:
	tox -e quality

requirements:
	pip install -r test_requirements.txt
	pip install -r docs/requirements.txt

test:
	tox

.PHONY: clean, quality, requirements

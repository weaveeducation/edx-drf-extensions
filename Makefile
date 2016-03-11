ROOT = $(shell echo "$$PWD")
COVERAGE = $(ROOT)/build/coverage
PACKAGE = edx_rest_framework_extensions

clean:
	find . -name '*.pyc' -delete
	coverage erase
	rm -rf build

quality:
	pep8 --config=.pep8 $(PACKAGE)
	pylint --rcfile=pylintrc $(PACKAGE)

requirements:
	pip install -r test_requirements.txt

test:
	nosetests --with-coverage --cover-inclusive --cover-branches \
		--cover-html --cover-html-dir=$(COVERAGE)/html/ \
		--cover-xml --cover-xml-file=$(COVERAGE)/coverage.xml \
		--cover-package=$(PACKAGE) $(PACKAGE)/

validate: clean test quality

.PHONY: clean, quality, requirements, validate

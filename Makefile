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
	django-admin.py test $(PACKAGE) --settings=test_settings --with-coverage --cover-package=$(PACKAGE)
	coverage report

validate: clean test quality

.PHONY: clean, quality, requirements, validate

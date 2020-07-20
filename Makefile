.PHONY: pypi, tag, shell, typecheck, pytest, pytest-pdb, test

pypi:
	poetry publish --build
	make tag

tag:
	git tag $$(python -c "from openapi_orm import __version__; print(__version__)")
	git push --tags

typecheck:
	pytype openapi_orm

pytest:
	py.test -v -s tests/

pytest-pdb:
	py.test -v -s --pdb --pdbcls=IPython.terminal.debugger:TerminalPdb tests/

test:
	$(MAKE) typecheck
	$(MAKE) pytest

PY?=python3

help:
	@echo 'Makefile to create the HTTP Observatory website'
	@echo ''
	@echo 'Usage:'
	@echo '    make publish                     (re)generate the site'
	@echo '    make devserver                   constantly regen site with automatic refreshing'

devserver:
	$(PY) devserver.py

publish:
	$(PY) render.py

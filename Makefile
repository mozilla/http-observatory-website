PY?=python3

help:
	@echo 'Makefile to create the HTTPS Observatory website'
	@echo ''
	@echo 'Usage:'
	@echo '    make publish                     (re)generate the site'
	@echo '    make devserver                   constantly regen site with automatic refreshing'

devserver:
	$(PY) devserver.py

deploy:
	git subtree push --prefix dist origin gh-pages

publish:
	$(PY) render.py

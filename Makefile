PY?=python3

help:
	@echo 'Makefile to create the HTTP Observatory website'
	@echo ''
	@echo 'Usage:'
	@echo '    make publish                     (re)generate the site'
	@echo '    make devserver                   constantly regen site with automatic refreshing'

devserver: publish
	$(PY) devserver.py

deploy:
	git subtree push --prefix dist origin gh-pages

publish:
	$(PY) render.py

PY?=python3

help:
	@echo 'Makefile to create the HTTP Observatory website'
	@echo ''
	@echo 'Usage:'
	@echo '    make publish                     (re)generate the site'
	@echo '    make devserver                   constantly regen site with automatic refreshing'

devserver: publish
	test ! -s config/nginx.pid || kill `cat config/nginx.pid`
	nginx -p . -c config/nginx.conf
	$(PY) devserver.py

deploy:
	git subtree push --prefix dist origin gh-pages

publish:
	$(PY) render.py

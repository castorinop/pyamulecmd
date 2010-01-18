coverage:
	nosetests --with-coverage --cover-package=ec --cover-erase

.PHONY: doc

doc: 
	pydoc -w ec ec.codes ec.conn ec.packet ec.tag ec.tagtypes
	mv ec*.html doc/

gencodes:
	sh -c "cd helper; ./gen_tagtypes.py > ../ec/tagtypes.py"
	sh -c "cd helper; ./gen_codes.py > ../ec/codes.py"

clean:
	rm -f .coverage
	find . -name '*.pyc' -exec rm {} \;

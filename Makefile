coverage:
	nosetests --with-coverage --cover-package=ec --cover-erase

gencodes:
	sh -c "cd helper; ./gen_tagtypes.py > ../ec/tagtypes.py"
	sh -c "cd helper; ./gen_codes.py > ../ec/codes.py"

clean:
	rm .coverage
	find . -name '*.pyc' -exec rm {} \;

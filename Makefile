coverage:
	nosetests --with-coverage --cover-package=ec

gencodes:
	sh -c "cd helper; ./gen_tagtypes.py > ../ec/tagtypes.py"

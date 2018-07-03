dumbno.pex: dumbno.py setup.py requirements.txt
	python setup.py bdist_wheel
	pex --disable-cache --python-shebang='/usr/bin/env python' -o dumbno.pex -c dumbno -f dist dumbno

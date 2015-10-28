dumbno.pex: dumbno.py setup.py requirements.txt
	pex --python-shebang='/usr/bin/env python' -o dumbno.pex . -c dumbno

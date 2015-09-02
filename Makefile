dumbno.pex: dumbno.py setup.py
	pex --python-shebang='/usr/bin/env python' -o dumbno.pex . -c dumbno

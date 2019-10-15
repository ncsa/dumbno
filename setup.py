from setuptools import setup

setup(name='dumbno',
    version='0.8.2',
    zip_safe=True,
    py_modules = ["dumbno"],
    install_requires=[
        "jsonrpclib-pelix==0.4.0",
    ],
    entry_points = {
        'console_scripts': [
            'dumbno = dumbno:main',
        ]
    }
)

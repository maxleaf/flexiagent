'apt-get install python3-pytest'

In source root: 'pytest-3 ./tests/'
Or in 'tests' : 'pytest-3'

'pytest-3 -k 01': run tests with '01' in filename, e.g. 01_test.py
'pytest-3 -s'   : don't capture stdout/stdout error, so they are printed onto screen immediately

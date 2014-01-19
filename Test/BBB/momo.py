import inspect
import os.path
import sys

__author__ = 'bazooka'

def test():
    print(os.path.abspath(os.path.dirname((inspect.getfile(inspect.currentframe())))))
    print(os.path.dirname(sys.argv[0]))
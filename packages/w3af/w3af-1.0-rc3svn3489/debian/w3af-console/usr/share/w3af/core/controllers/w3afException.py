'''
w3afException.py

Copyright 2006 Andres Riancho

This file is part of w3af, w3af.sourceforge.net .

w3af is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

w3af is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with w3af; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

'''

class w3afException(Exception):
    '''
    A small class that defines a w3afException.
    '''
    
    def __init__(self, value):
        Exception.__init__( self )
        self.value = value
    
    def __str__(self):
        return self.value

class w3afRunOnce(Exception):
    '''
    A small class that defines an exception to be raised by plugins that dont want to be runned anymore.
    '''
    def __init__(self, value=''):
        Exception.__init__( self )
        self.value = value
    
    def __str__(self):
        return self.value
        
class w3afFileException(Exception):
    '''
    A small class that defines a w3af File Exception.
    '''
    pass
    
class w3afMustStopException(Exception):
    '''
    If this exception is catched by the core, then it should stop the whole process. This exception is raised in
    a few places. NOT to be used extensively.
    '''
    pass

class w3afProxyException(w3afException):
    '''
    A small class that defines a w3af Proxy Exception.
    '''
    pass

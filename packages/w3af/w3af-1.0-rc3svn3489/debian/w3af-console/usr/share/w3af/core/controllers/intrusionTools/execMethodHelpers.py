'''
execMethodHelpers.py

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

import core.controllers.outputManager as om
from core.controllers.w3afException import *
from core.data.fuzzer.fuzzer import *

def osDetectionExec( execMethod ):
    '''
    Uses the execMethod to run remote commands and determine what's the remote OS is
    and returns a string with 'windows' or 'linux' or raises a w3afException if unknown.
    '''
    try:
        linux1 = apply( execMethod, ( 'echo -n w3af',))
        linux2 = apply( execMethod, ( 'head -n 1 /etc/passwd',))
    except:
        pass
    else:
        if 'w3af' == linux1 and ':' in linux2:
            om.out.debug('Identified remote OS as Linux, returning "linux".')
            return 'linux'
        
    try:
        # Try if it's a windows system
        win1 = apply( execMethod, ( 'type %SYSTEMROOT%\\win.ini',))
        win2 = apply( execMethod, ( 'echo /?',))
    except:
        pass
    else:
        if '[fonts]' in win1 and 'ECHO' in win2:
            om.out.debug('Identified remote OS as Windows, returning "windows".')
            return 'windows'
    
    raise w3afException('Failed to get/identify the remote OS.')

def getRemoteTempFile( execMethod ):
    '''
    @return: The name of a file in the remote file system that the user that I'm executing commands with
    can write, read and execute. The normal responses for this are files in /tmp/ or %TEMP% depending
    on the remote Os.
    '''
    os = osDetectionExec( execMethod )
    if  os == 'windows':
        _filename = apply( execMethod, ('echo %TEMP%',) ).strip() + '\\'
        _filename += createRandAlNum(6)
        
        # verify existance
        dirRes = apply( execMethod, ('dir '+_filename,) ).strip().lower()
        if 'not found' in dirRes:
            # Shit, the file exists, run again and see what we can do
            return getRemoteTempFile( execMethod )
        else:
            return _filename
        return _filename
        
        
    elif os == 'linux':
        _filename = '/tmp/' + createRandAlNum( 6 )
        
        # verify existance
        lsRes = apply( execMethod, ('ls '+_filename,) ).strip()
        if _filename == lsRes:
            # Shit, the file exists, run again and see what we can do
            return getRemoteTempFile( execMethod )
        else:
            return _filename
    else:
        raise w3afException('Failed to create filename for a temporary file in the remote host.')


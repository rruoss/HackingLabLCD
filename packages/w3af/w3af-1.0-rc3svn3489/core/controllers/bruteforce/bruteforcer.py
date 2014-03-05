'''
bruteforcer.py

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
from core.controllers.w3afException import w3afException
from core.data.parsers.urlParser import *
import core.data.kb.knowledgeBase as kb
import os.path
from core.controllers.misc.make_leet import make_leet


class bruteforcer:
    '''
    This class is a helper for bruteforcing any login.
    
    @author: Andres Riancho ( andres.riancho@gmail.com )
    '''

    def __init__(self):
        # Config params
        self._usersFile = os.path.join('core', 'controllers', 'bruteforce','users.txt')
        self._passwdFile = os.path.join('core','controllers','bruteforce','passwords.txt')
        self._useMailUsers = True
        self._useSvnUsers = True
        self._stopOnFirst = True
        self._passEqUser = True
        self._l337_p4sswd = True
        self._useMails = True
        self._useProfiling = True
        self._profilingNumber = 50
        
        
        # Internal vars
        self._alreadyInit = False
        self._usersFD = None
        self._passwordsFD = None
        self._eofPasswords = False
        self._eofUsers = False
        self._nextUser = True
        self._leeted_passwords = []
        
    def init( self ):
        '''
        Open files and init some variables
        '''
        if not self._alreadyInit:
            self._alreadyInit = True
            try:
                self._usersFD = open( self._usersFile )
            except:
                raise w3afException('Cant open ' + self._usersFile + ' file.')
            try:
                self._passwordsFD = open( self._passwdFile )
            except:
                raise w3afException('Cant open ' + self._passwdFile + ' file.')
            
            self._genSpecialPasswords()
            self._genSpecialUsers()
    
    def _genSpecialUsers( self ):
        '''
        Generate special passwords from URL, password profiling, etc.
        '''
        self._specialUserIndex = -1
        self._specialUsers = []
        self._specialUsers.append( getDomain(self._url) )
        
        if self._useMailUsers:
            mails = kb.kb.getData( 'mails', 'mails' )
            self._specialUsers.extend( [ v['user'] for v in mails ]  )
            
        if self._useMails:
            mails = kb.kb.getData( 'mails', 'mails' )
            self._specialUsers.extend(  [ v['mail'] for v in mails ] )
        
        if self._useSvnUsers:
            users = kb.kb.getData( 'svnUsers', 'users' )
            self._specialUsers.extend( [ v['user'] for v in users ]  )
            
        self._specialUsers = list(set(self._specialUsers))
        
    def _genSpecialPasswords( self ):
        '''
        Generate special passwords from URL, password profiling, etc.
        '''
        self._specialPassIndex = -1
        self._specialPasswords = []
        self._specialPasswords.append( getDomain(self._url) )
        self._specialPasswords.append( getRootDomain(self._url) )
        if self._useProfiling:
            self._specialPasswords.extend( self._getProfilingResults() )
        
        # Handle the leet passwords:
        if self._l337_p4sswd:
            leet_passwds = []
            for pwd in self._specialPasswords:
                leet_passwds.extend( make_leet(pwd) )
            self._specialPasswords.extend( leet_passwds )
        
        # uniq
        self._specialPasswords = list(set(self._specialPasswords))
            
    def stop( self ):
        self._passwordsFD.close()
        self._usersFD.close()
    
    def _getPassword( self, user ):
        '''
        Get a password from the password file.
        '''
        passwd = None
        
        if self._eofPasswords:
            # The file with passwords is now over, here i'll add the "special" passwords
            self._specialPassIndex += 1
            
            if len( self._specialPasswords ) > self._specialPassIndex:
                passwd = self._specialPasswords[ self._specialPassIndex ]
            else:
                passwd = user
                self._specialPassIndex = -1
                self._eofPasswords = False
                self._nextUser = True
            
        else:
            
            if self._leeted_passwords and self._l337_p4sswd:
                # return a leet version of the password that was read from the file a couple
                # of lines after this one:
                passwd = self._leeted_passwords.pop()
            
            else:
                passwd = self._passwordsFD.readline().strip()
                # here we create the leet passwords from the file
                self._leeted_passwords.extend( make_leet(passwd) )
                
                if passwd == '' :
                    self._passwordsFD.seek(0)
                    self._eofPasswords = True

        return passwd
    
    def _getUser( self ):
        '''
        Get the user for this combination.
        '''
        user = None
        
        if self._eofUsers:
            # The file with users is now over, here i'll add the "special" users
            
            # This variable (self._nextUser) is modified to True by the _getPassword method.
            if self._nextUser:
                self._specialUserIndex += 1
                self._nextUser = False
            
            if len( self._specialUsers ) > self._specialUserIndex:
                user = self._specialUsers[ self._specialUserIndex ]
            else:
                self._specialPassIndex = -1
                raise w3afException('No more users to test.')
            
        else:
            if self._nextUser:
                self._nextUser = False
                user = self._user = self._usersFD.readline().strip()
                if user == '':
                    self._eofUsers = True
            else:
                user = self._user
                    
        return user
    
    def getNextString( self ):
        '''
        This is used for "password only" logins.
        '''
        return self._getUser()
    
    def getNext( self ):
        '''
        @return: The next user/password combination
        '''     
        user = self._getUser()
        passwd = self._getPassword( user )
        
        return user, passwd
        
    def getNextPassword(self):
        '''
        @return: The next password to be tested. 
        @raise w3afException: when there are no more passwords.
        
        This is used by parts of the framework that at some point need passwords, WITHOUT
        an associated username. If you want a username and password combination, please use
        getNext().
        
        Calling getNextPassword() and getNext() together in the same loop will break things.
        '''
        #   This is just for the first call:
        if self._nextUser:
            self._nextUser = False
        
        #   The _getPassword method will change the self._nextUser variable when there are no more
        #   passwords for the 'admin' user.
        password = self._getPassword('admin')
        
        if self._nextUser:
            raise w3afException('No more passwords.')
        else:
            return password
    
    def _getProfilingResults(self):
        '''
        This method is called when the plugin wont be used anymore.
        '''
        def sortfunc(x,y):
            return cmp(y[1],x[1])
            
        items = kb.kb.getData( 'passwordProfiling', 'passwordProfiling' ).items()
        items.sort(sortfunc)
        
        listLen = len(items)
        if listLen == 0:
            msg = 'No password profiling information collected, please try to enable webSpider'
            msg += ' plugin and try again.'
            om.out.information( msg )
        if listLen > self._profilingNumber:
            xLen = self._profilingNumber
        else:
            xLen = listLen
        
        return [ x[0] for x in items[:xLen] ]
        
    def setUsersFile( self, usersFile ):
        self._usersFile = usersFile
    
    def getUsersFile( self ): return self._usersFile
    
    def setPassFile( self, passwdFile ):
        self._passwdFile = passwdFile
    
    def getPassFile( self ): return self._passwdFile
    
    def setPassEqUser( self, tf ):
        self._passEqUser = tf
        
    def getPassEqUser( self ): return self._passEqUser
    
    def setUseMailUsers( self, tf ):
        self._useMailUsers = tf
        
    def getUseMailUsers( self ): return self._useMailUsers
    
    def setUseMails( self, tf ):
        self._useMails = tf
        
    def getUseMails( self ): return self._useMails

    def setUseSvnUsers( self, sv ):
        self._useSvnUsers = sv
        
    def getUseSvnUsers( self ): return self._useSvnUsers

    def setLeetPasswd( self, lp ):
        self._l337_p4sswd = lp
        
    def getLeetPasswd( self ): return self._l337_p4sswd

    def setUseProfiling( self, tf ):
        self._useProfiling = tf
        
    def getUseProfiling( self ): return self._useProfiling
    
    def setProfilingNumber( self, number ):
        self._profilingNumber = number
        
    def getProfilingNumber( self ): return self._profilingNumber
    
    def setURL( self, url ):
        self._url = url
    
    def getURL( self ): return self._url
    
    

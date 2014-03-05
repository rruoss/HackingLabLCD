'''
httpAuthDetect.py

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

# options
from core.data.options.option import option
from core.data.options.optionList import optionList

from core.controllers.basePlugin.baseGrepPlugin import baseGrepPlugin

import core.data.kb.knowledgeBase as kb
import core.data.kb.info as info
import core.data.kb.vuln as vuln
import core.data.constants.severity as severity

import re


class httpAuthDetect(baseGrepPlugin):
    '''
    Find responses that indicate that the resource requires auth.
      
    @author: Andres Riancho ( andres.riancho@gmail.com )
    '''

    def __init__(self):
        baseGrepPlugin.__init__(self)
        
        self._auth_uri_regex = re.compile('.*://[\w%]*?:[\w%]*?@[\w\.]{3,40}')

    def grep(self, request, response):
        '''
        Verify if I find 401 or authentication URIs like http://user:pass@domain.com/
        
        @parameter request: The HTTP request object.
        @parameter response: The HTTP response object
        @return: None
        '''
        already_reported = [ u.getURL() for u in kb.kb.getData( 'httpAuthDetect', 'auth' ) ]
        
        # If I have a 401 code, and this URL wasn't already reported...
        if response.getCode() == 401 and \
        response.getURL() not in already_reported:
            
            # Perform all the work in this method
            self._analyze_401(response)
            
        else:
            
            # I get here for "normal" HTTP 200 responses
            self._find_auth_uri(response)
            

    def _find_auth_uri(self, response):
        '''
        Analyze a 200 response and report any findings of http://user:pass@domain.com/
        @return: None
        '''
        if self._auth_uri_regex.match( response.getURI() ):
            # An authentication URI was found!
            
            v = vuln.vuln()
            v.setURL( response.getURL() )
            v.setId( response.id )
            desc = 'The resource: "'+ response.getURI() + '" has a user and password in the URI.'
            v.setDesc( desc )
            v.setSeverity(severity.HIGH)
            v.setName( 'Basic HTTP credentials' )
            v.addToHighlight( response.getURI() )
            
            kb.kb.append( self , 'userPassUri' , v )
            om.out.vulnerability( v.getDesc(), severity=v.getSeverity() )
            
        # I also search for authentication URI's in the body
        # I know that by doing this I loose the chance of finding hashes in PDF files, but...
        # This is much faster
        if response.is_text_or_html():
            for authURI in self._auth_uri_regex.findall( response.getBody() ):
                v = vuln.vuln()
                v.setURL( response.getURL() )
                v.setId( response.id )
                msg = 'The resource: "'+ response.getURL() + '" has a user and password in the'
                msg += ' body. The offending URL is: "' + authURI + '".'
                v.setDesc( msg )
                
                v.setSeverity(severity.HIGH)
                v.setName( 'Basic HTTP credentials' )
                v.addToHighlight( authURI )
                
                kb.kb.append( self , 'userPassUri' , v )
                om.out.vulnerability( v.getDesc(), severity=v.getSeverity() )
                
    def _analyze_401(self, response):
        '''
        Analyze a 401 response and report it.
        @return: None
        '''
        # Get the realm
        realm = None
        for key in response.getHeaders():
            if key.lower() == 'www-authenticate':
                realm = response.getHeaders()[ key ]
                break
                
        if realm == None:
            # Report this strange case
            i = info.info()
            i.setName('Authentication without www-authenticate header')
            i.setURL( response.getURL() )
            i.setId( response.id )
            i.setDesc( 'The resource: "'+ response.getURL() + '" requires authentication ' +
            '(HTTP Code 401) but the www-authenticate header is not present. This requires ' + 
            'human verification.')
            kb.kb.append( self , 'non_rfc_auth' , i )
        
        else:
            # Report the common case, were a realm is set.
            i = info.info()
            if 'ntlm' in realm.lower():
                i.setName('NTLM authentication')
            else:
                i.setName('HTTP Basic authentication')
            i.setURL( response.getURL() )
            i.setId( response.id )
            i.setDesc( 'The resource: "'+ response.getURL() + '" requires authentication.' +
            ' The realm is: "' + realm + '".')
            i['message'] = realm
            i.addToHighlight( realm )
            
            kb.kb.append( self , 'auth' , i )
            
        om.out.information( i.getDesc() )
        
    def setOptions( self, OptionList ):
        pass
    
    def getOptions( self ):
        '''
        @return: A list of option objects for this plugin.
        '''    
        ol = optionList()
        return ol

    def getPluginDeps( self ):
        '''
        @return: A list with the names of the plugins that should be runned before the
        current one.
        '''
        return []
    
    def getLongDesc( self ):
        '''
        @return: A DETAILED description of the plugin functions and features.
        '''
        return '''
        This plugin greps every page and finds responses that indicate that the resource requires
        authentication.
        '''

'''
objects.py

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

from core.data.db.temp_persist import disk_list

import re


class objects(baseGrepPlugin):
    '''
    Grep every page for objects and applets.
      
    @author: Andres Riancho ( andres.riancho@gmail.com )
    '''

    def __init__(self):
        baseGrepPlugin.__init__(self)
        self._object = re.compile(r'< *object([^>]*)>', re.IGNORECASE)
        self._applet = re.compile(r'< *applet([^>]*)>', re.IGNORECASE)
        self._already_added_object = disk_list()
        self._already_added_applet = disk_list()

    def grep(self, request, response):
        '''
        Plugin entry point. Parse the object tags.
        
        @parameter request: The HTTP request object.
        @parameter response: The HTTP response object
        @return: None
        '''

        if response.is_text_or_html() and response.getURL() not in self._already_added_object:
            res = self._object.findall( response.getBody() )
            if res:
                i = info.info()
                i.setName('Object tag')
                i.setURL( response.getURL() )
                i.setId( response.id )
                i.setDesc( 'The URL: "' + i.getURL() + '" has an object tag.' )          
                for finding in res:
                    i.addToHighlight( finding )

                kb.kb.append( self, 'object', i )
                self._already_added_object.append( response.getURL() )
        
        if response.getURL() not in self._already_added_applet:
            res = self._applet.findall( response.getBody() )
            if res:
                i = info.info()
                i.setName('Applet tag')
                i.setURL( response.getURL() )
                i.setId( response.id )
                i.setDesc( 'The URL: "' + i.getURL() + '" has an applet tag.' )          
                for finding in res:
                    i.addToHighlight( finding )

                kb.kb.append( self, 'applet', i )
                self._already_added_applet.append( response.getURL() )
    
    def setOptions( self, OptionList ):
        pass
    
    def getOptions( self ):
        '''
        @return: A list of option objects for this plugin.
        '''    
        ol = optionList()
        return ol

    def end(self):
        '''
        This method is called when the plugin wont be used anymore.
        '''
        # Print objects
        self.printUniq( kb.kb.getData( 'objects', 'object' ), 'URL' )
        
        # Print applets
        self.printUniq( kb.kb.getData( 'objects', 'applet' ), 'URL' )
        
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
        This plugin greps every page for applets and other types of objects.
        '''

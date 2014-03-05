'''
googleSpider.py

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

from core.controllers.basePlugin.baseDiscoveryPlugin import baseDiscoveryPlugin
from core.controllers.w3afException import w3afException
from core.controllers.w3afException import w3afRunOnce
from core.data.searchEngines.googleSearchEngine import googleSearchEngine as google

from core.controllers.misc.is_private_site import is_private_site
import core.data.parsers.urlParser as urlParser

from urllib2 import URLError


class googleSpider(baseDiscoveryPlugin):
    '''
    Search google using google API to get new URLs
    @author: Andres Riancho ( andres.riancho@gmail.com )
    '''

    def __init__(self):
        baseDiscoveryPlugin.__init__(self)
        
        # Internal variables
        self._run = True
        self._fuzzableRequests = []
        
        # User variables
        self._key = ''
        self._result_limit = 300
        
    def discover(self, fuzzableRequest ):
        '''
        @parameter fuzzableRequest: A fuzzableRequest instance that contains 
                                                    (among other things) the URL to test.
        '''
        if not self._run:
            # This will remove the plugin from the discovery plugins to be runned.
            raise w3afRunOnce()
        else:
            # I will only run this one time. All calls to googleSpider return the same url's
            self._run = False
            
            google_se = google( self._urlOpener, self._key )
            
            domain = urlParser.getDomain( fuzzableRequest.getURL() )
            if is_private_site( domain ):
                msg = 'There is no point in searching google for "site:'+ domain + '".'
                msg += ' Google doesnt index private pages.'
                raise w3afException( msg )

            try:
                results = google_se.getNResults('site:'+ domain, self._result_limit)
            except w3afException, w3:
                om.out.error(str(w3))
                # If I found an error, I don't want to be run again
                raise w3afRunOnce()
            else:
                # Happy happy joy, no error here!
                for res in results:
                    targs = (res.URL,)
                    self._tm.startFunction( target=self._generateFuzzableRequests, 
                                                        args=targs, ownerObj=self )
                self._tm.join( self )
        return self._fuzzableRequests
    
    def _generateFuzzableRequests( self, url ):
        '''
        Generate the fuzzable requests based on the URL, which is a result from google search.
        
        @parameter url: A URL from google.
        '''
        try:
            response = self._urlOpener.GET( url, useCache=True)
        except KeyboardInterrupt, k:
            raise k
        except w3afException, w3:
            om.out.debug('w3afException while fetching page in googleSpider: ' + str(w3) )
        except URLError, url_error:
            om.out.debug('URL Error while fetching page in googleSpider, error: ' + str(url_error) )
        else:
            fuzzReqs = self._createFuzzableRequests( response )
            self._fuzzableRequests.extend( fuzzReqs )
    
    def getOptions( self ):
        '''
        @return: A list of option objects for this plugin.
        '''
        d1 = 'Google API License key'
        h1 = 'To use this plugin you have to own your own google API license key OR you can'
        h1 += ' directly use the search engine using clasic HTTP. If this parameter is left blank,'
        h1 += ' the search engine will be used, otherwise the google webservice will be used.'
        h1 += ' Go to http://www.google.com/apis/ to get more information.'
        o1 = option('key', self._key, d1, 'string', help=h1)
        
        d2 = 'Fetch the first "resultLimit" results from the Google search'
        o2 = option('resultLimit', self._result_limit, d2, 'integer')

        ol = optionList()
        ol.add(o1)
        ol.add(o2)
        return ol

    def setOptions( self, optionsMap ):
        '''
        This method sets all the options that are configured using the user interface 
        generated by the framework using the result of getOptions().
        
        @parameter OptionList: A dictionary with the options for the plugin.
        @return: No value is returned.
        ''' 
        self._key = optionsMap['key'].getValue()
        self._result_limit = optionsMap['resultLimit'].getValue()

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
        This plugin finds new URL's using google. It will search for "site:domain.com" and do GET
        requests all the URL's found in the result.
        
        Two configurable parameters exist:
            - resultLimit
            - key
        
        Valid google API licenses are only the *old ones*.
        '''

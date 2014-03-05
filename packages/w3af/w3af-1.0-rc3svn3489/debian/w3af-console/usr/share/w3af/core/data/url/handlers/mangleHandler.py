'''
mangleHandler.py

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

import urllib2
import core.controllers.outputManager as om
import core.data.request.fuzzableRequest as fuzzableRequest
import core.data.url.httpResponse as httpResponse
from core.data.url.handlers.keepalive import HTTPResponse as kaHTTPResponse
import core.data.url.handlers.logHandler
from core.data.parsers.urlParser import getDomain


class mangleHandler(urllib2.BaseHandler):
    """
    Call mangle plugins for each request and response.
    """
    
    handler_order = core.data.url.handlers.logHandler.logHandler.handler_order - 2
    
    def __init__(self, pluginList):
        self._pluginList = pluginList

        
    def _urllibReq2fr( self, request ):
        '''
        Convert a urllib2 request object to a fuzzableRequest.
        Used in http_request.
        
        @parameter request: A urllib2 request obj.
        @return: A fuzzableRequest.
        '''
        fr = fuzzableRequest.fuzzableRequest()
        fr.setURI( request.get_full_url() )
        fr.setMethod( request.get_method() )
        
        headers = request.headers
        for i in request.unredirected_hdrs.keys():
            headers[ i ] = request.unredirected_hdrs[ i ]
        fr.setHeaders( headers )
        
        if request.get_data() == None:
            fr.setData( '' )
        else:
            fr.setData( request.get_data() )
        return fr
    
    def _fr2urllibReq( self, fuzzableRequest ):
        '''
        Convert a fuzzableRequest to a urllib2 request object. 
        Used in http_request.
        
        @parameter fuzzableRequest: A fuzzableRequest.
        @return: A urllib2 request obj.
        '''
        host = getDomain( fuzzableRequest.getURL() )
        
        if fuzzableRequest.getMethod().upper() == 'GET':
            data = None
        else:
            data = fuzzableRequest.getData()
        req = urllib2.Request( fuzzableRequest.getURI(), data=data\
        , headers=fuzzableRequest.getHeaders(), origin_req_host=host )
        return req
        
    def http_request(self, request):
        if len( self._pluginList ):
            fr = self._urllibReq2fr( request )
            
            for plugin in self._pluginList:
                fr = plugin.mangleRequest( fr )
            
            request = self._fr2urllibReq( fr )
        return request

    def http_response(self, request, response):
        if len( self._pluginList ):
            # Create the httpResponse object
            code, msg, hdrs = response.code, response.msg, response.info()
            url = response.geturl()
            body = response.read()
            # Id is not here, the mangle is done BEFORE logging
            # id = response.id
            httpRes = httpResponse.httpResponse( code, body, hdrs, url, url, msg=msg)
            
            for plugin in self._pluginList:
                plugin.mangleResponse( httpRes )
            
            if response._connection.sock == None:
                # This fixes bug #1982106
                # https://sourceforge.net/tracker/index.php?func=detail&aid=1982106&group_id=170274&atid=853652
                # Returning None is like saying "I don't know what to do with this, let the next handler manage it".
                ### FIXME: Does this work?
                return None
            else:
                response = self._httpResponse2httplib( response, httpRes )
        return response

    def _httpResponse2httplib( self, originalResponse, mangledResponse ):
        '''
        Convert an httpResponse.httpResponse object to a httplib.httpresponse subclass that I created in keepalive.
        
        @parameter httpResponse: httpResponse.httpResponse object
        @return: httplib.httpresponse subclass 
        '''
        kaRes = kaHTTPResponse( originalResponse._connection.sock, debuglevel=0, strict=0, method=None )
        kaRes.setBody( mangledResponse.getBody() )
        kaRes.headers = mangledResponse.getHeaders()
        kaRes.code = mangledResponse.getCode()
        kaRes._url = mangledResponse.getURI()
        kaRes.msg = originalResponse.msg
        return kaRes
    
    https_request = http_request
    https_response = http_response


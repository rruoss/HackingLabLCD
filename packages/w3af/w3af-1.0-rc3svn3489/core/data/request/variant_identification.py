'''
variant_identification.py

Copyright 2010 Andres Riancho

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

import core.data.parsers.urlParser as urlParser
import core.data.request.httpQsRequest as httpQsRequest
import core.data.parsers.urlParser as urlParser


def are_variants( url_a ,  url_b ):
    '''
    This function analyzes if two URLs are variants. Two requests are variants if:
        - They have the same URL
        - They have the same method
        - They have the same parameters
        - The values for each parameter have the same type (int / string)
    
    @parameter url_a: The URL we want to analyze
    @parameter url_b: The other URL we want to analyze
    @return: True if the URLs are variants.
    '''
    qs_a = urlParser.getQueryString( url_a )
    qsr_a = httpQsRequest.httpQsRequest()
    qsr_a.setURL( urlParser.uri2url(url_a) )
    qsr_a.setDc( qs_a )

    qs_b = urlParser.getQueryString( url_b )
    qsr_b = httpQsRequest.httpQsRequest()
    qsr_b.setURL( urlParser.uri2url(url_b) )
    qsr_b.setDc( qs_b )
    return qsr_a.is_variant_of( qsr_b )

    


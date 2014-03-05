# OpenVAS Vulnerability Test
# $Id$
# Description: Implementation of common https functions
#
# Authors:
# Vlatko Kosturjak <kost@linux.hr>
#
# Copyright:
# Copyright (C) 2008 Vlatko Kosturjak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

function https_req_get(port, request)
{
    if(get_port_state(port))
    {

	 soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
	 if(soc)
	 {
	    send(socket:soc, data:string(request,"\r\n"));
            x = 0;
            while(ret = http_recv(socket:soc)) { 
              x++;
              result += ret;
              if(x > 25)break;
            }
	    close(soc);
	    return(result);
        }
    }
}

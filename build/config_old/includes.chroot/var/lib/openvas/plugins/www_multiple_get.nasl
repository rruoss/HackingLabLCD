# OpenVAS Vulnerability Test
# $Id: www_multiple_get.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Several GET locks web server
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

include("revisions-lib.inc");
tag_summary = "The remote web server shuts down temporarily or blacklists
us when it receives several GET HTTP/1.0 requests in a row.

This might trigger false positive in generic destructive 
or DoS plugins.
** OpenVAS enabled some countermeasures, however they might be 
** insufficient.";

if(description)
{
 script_id(18366);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name( "Several GET locks web server");
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);

 script_summary( "Several GET requests in a row temporarily shut down the web server");
 # It is not really destructive, but it is useless in safe_checks mode
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family("Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www",80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include('global_settings.inc');
include('http_func.inc');

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

# CISCO IP Phone 7940 behaves correctly on a HTTP/1.1 request,
# so we forge a crude HTTP/1.0 request. 
# r = http_get(port: port, item: '/'); 
r = string("GET / HTTP/1.0\r\n", "Host: ", get_host_name(),"\r\n");
max = 12;

for (i = 0; i < max; i ++) 
{
 soc = http_open_socket(port);
 if (! soc) break;
 send(socket: soc, data: r);
 recv(socket: soc, length: 8192);
 http_close_socket(soc);
}

debug_print('i=', i, '\n');
if (i == 0)
 debug_print('Server is dead?');
else if (i < max)
{
 debug_print('Web server rejected connections after ', i, ' connections\n');
 set_kb_item(name: 'www/multiple_get/'+port, value: i);
 if (report_verbosity > 1)	# Verbose report
  security_note(port);
}



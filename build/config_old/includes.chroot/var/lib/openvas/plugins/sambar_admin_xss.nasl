# OpenVAS Vulnerability Test
# $Id: sambar_admin_xss.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sambar Server Administrative Interface multiple XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host runs the Sambar web server. 

The remote version of this software is vulnerable to multiple cross site 
scripting attacks.

With a specially crafted URL, an attacker can use the remote host to perform
a cross site scripting against a third party.";

tag_solution = "Upgrade at least to version 6.2.1";

#  Ref: jamie fisher <contact_jamie_fisher@yahoo.co.uk>

if (description)
{
 script_id(18364);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(13722);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Sambar Server Administrative Interface multiple XSS");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 script_summary("Determine if Sambar server is prone to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_dependencies("cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach d ( cgi_dirs() )
{
 url = string(d, '/search/results.stm?indexname=>"><script>foo</script>&style=fancy&spage=60&query=Folder%20name');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
#<FONT SIZE="+3">S</FONT>AMBAR 
#<FONT SIZE="+3">S</FONT>EARCH 
#<FONT SIZE="+3">E</FONT>NGINE</H2>
 
 if ( ">S</FONT>AMBAR" >< buf  && "<script>foo</script>" >< buf )
   {
    security_warning(port);
    exit(0);
   }
}

# OpenVAS Vulnerability Test
# $Id: iis5_isapi_printer.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IIS 5 .printer ISAPI filter applied
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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
tag_summary = "Remote Web server supports Internet Printing Protocol

Description :

IIS 5 has support for the Internet Printing Protocol(IPP), which is 
enabled in a default install. The protocol is implemented in IIS5 as an 
ISAPI extension. At least one security problem (a buffer overflow)
has been found with that extension in the past, so we recommend
you disable it if you do not use this functionality.";

tag_solution = "To unmap the .printer extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
and remove the reference to .printer from the list.";

if(description)
{
 script_id(10661);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 
 name = "IIS 5 .printer ISAPI filter applied";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Tests for IIS5 .printer ISAPI filter";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2001 Matt Moore");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://online.securityfocus.com/archive/1/181109");
 exit(0);
}

# Actual check starts here...
# Check makes a request for NULL.printer

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);


sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/NULL.printer", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("Error in web printer install" >< r)	
 	security_note(port);

}

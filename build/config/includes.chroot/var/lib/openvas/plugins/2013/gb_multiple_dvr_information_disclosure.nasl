###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_dvr_information_disclosure.nasl 11 2013-10-27 10:12:02Z jan $
#
# Multiple DVR Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "Multiple DVR devices are prone to a remote information-
disclosure vulnerability.

Successful exploits will allow attackers to obtain sensitive
information, such as credentials, that may aid in further attacks 
from '/DVR.cfg'.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103653";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(57579);
 script_cve_id("CVE-2013-1391");
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Multiple DVR Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57579");
 script_xref(name : "URL" , value : "http://www.securitybydefault.com/2013/01/12000-grabadores-de-video-expuestos-en.html");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-02-01 10:51:23 +0100 (Fri, 01 Feb 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to read the /DVR.cfg");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = '/DVR.cfg'; 
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("WEB_ADMIN_ID" >< buf && "WEB_ADMIN_PWD" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(0);

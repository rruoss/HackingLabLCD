###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_toshiba_e_studio_50168.nasl 13 2013-10-27 12:16:33Z jan $
#
# Multiple Toshiba e-Studio Devices Security Bypass Vulnerability
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
tag_summary = "Multiple Toshiba e-Studio devices are prone to a security-bypass
vulnerability.

Successful exploits will allow attackers to bypass certain security
restrictions and gain access in the context of the device.";


if (description)
{
 script_id(103301);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)");
 script_bugtraq_id(50168);

 script_name("Multiple Toshiba e-Studio Devices Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50168");
 script_xref(name : "URL" , value : "http://www.eid.toshiba.com.au/n_mono_search.asp");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if Toshiba e-Studio device is prone to a security-bypass vulnerability.");
 script_category(ACT_ATTACK);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: TOSHIBA" >!< banner)exit(0);

url = string("/TopAccess//Administrator/Setup/ScanToFile/List.htm"); 

if(http_vuln_check(port:port, url:url,pattern:"<TITLE>Save as file Setting",extra_check:make_list("Password","Protocol","Server Name"))) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);

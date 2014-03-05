###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asus_rt-n56u_49308.nasl 13 2013-10-27 12:16:33Z jan $
#
# ASUS RT-N56U Wireless Router 'QIS_wizard.htm' Password Information Disclosure Vulnerability
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
tag_summary = "ASUS RT-N56U wireless router is prone to an information-disclosure
vulnerability that exposes sensitive information.

Successful exploits will allow unauthenticated attackers to obtain
sensitive information of the device such as administrative password,
which may aid in further attacks.

ASUS RT-N56U firmware version 1.0.1.4 is vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103228);
 script_version("$Revision: 13 $");
 script_cve_id("CVE-2011-4497");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-08-26 14:51:18 +0200 (Fri, 26 Aug 2011)");
 script_bugtraq_id(49308);
 script_tag(name:"cvss_base", value:"3.3");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:N/A:N");
 script_name("ASUS RT-N56U Wireless Router 'QIS_wizard.htm' Password Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49308");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/200814");
 script_xref(name : "URL" , value : "http://www.asus.com/Networks/Wireless_Routers/RTN56U/");
 script_xref(name : "URL" , value : "http://www.asus.com/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if SUS RT-N56U wireless router is prone to an information-disclosure vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || 'Basic realm="RT-N56U"' >!< banner)exit(0);

url = string(dir, "/QIS_wizard.htm?flag=detect."); 

if(http_vuln_check(port:port, url:url,pattern:"<title>ASUS Wireless Router RT-N56U - Quickly Internet Setup")) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);


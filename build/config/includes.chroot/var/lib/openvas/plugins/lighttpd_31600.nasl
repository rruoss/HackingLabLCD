###############################################################################
# OpenVAS Vulnerability Test
# $Id: lighttpd_31600.nasl 14 2013-10-27 12:33:37Z jan $
#
# Lighttpd 'mod_userdir' Case Sensitive Comparison Security Bypass Vulnerability
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
tag_summary = "The 'lighttpd' program is prone to a security-bypass vulnerability
that occurs in the 'mod_userdir' module.

Attackers can exploit this issue to bypass certain security
restrictions and obtain sensitive information. This may lead to
other attacks.

Versions prior to 'lighttpd' 1.4.20 are vulnerable.";

tag_solution = "The vendor has released lighttpd 1.4.20 to address this issue. Please
see the references for more information.";

if (description)
{
 script_id(100449);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-14 12:06:50 +0100 (Thu, 14 Jan 2010)");
 script_bugtraq_id(31600);
 script_cve_id("CVE-2008-4360");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_tag(name:"risk_factor", value:"High");

 script_name("Lighttpd 'mod_userdir' Case Sensitive Comparison Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/31600");
 script_xref(name : "URL" , value : "http://www.lighttpd.net/");
 script_xref(name : "URL" , value : "http://www.lighttpd.net/security/lighttpd_sa_2008_06.txt");

 script_description(desc);
 script_summary("Determine if lighttpd version is < 1.4.20");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("lighttpd/" >!< banner)exit(0);

version = eregmatch(pattern: "Server: lighttpd/([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

   if(version_is_less(version: version[1], test_version: "1.4.20")) {
        security_hole(port:port);
        exit(0); 
   }

exit(0);


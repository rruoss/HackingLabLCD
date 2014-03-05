###############################################################################
# OpenVAS Vulnerability Test
# $Id: moodle_37244.nasl 15 2013-10-27 12:49:54Z jan $
#
# Moodle Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_summary = "Moodle is prone to multiple vulnerabilities including cross-site
request-forgery, security bypass, information-disclosure and SQL-
injection issues.

Attackers can exploit these issues to bypass certain security
restrictions, gain access to sensitive information, perform
unauthorized actions, compromise the application, access or modify
data, or exploit latent vulnerabilities in the underlying database.

These issues affect Moodle versions prior to 1.8.11 and 1.9.7.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100384);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-12-09 12:14:51 +0100 (Wed, 09 Dec 2009)");
 script_cve_id("CVE-2009-4297");
 script_bugtraq_id(37244);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Moodle Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37244");
 script_xref(name : "URL" , value : "http://www.moodle.org");
 script_xref(name : "URL" , value : "http://moodle.org/security/");

 script_description(desc);
 script_summary("Determine if the Moodle version is < 1.8.11 or < 1.9.7");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_moodle_cms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Moodle/Version");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/moodle")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {
 if(vers =~ "1\.8") {
   if(version_is_less(version: vers, test_version: "1.8.11")) {
       security_hole(port:port);
       exit(0);
   }
 } else if(vers =~ "1\.9") {
    if(version_is_less(version: vers, test_version: "1.9.7")) {
      security_hole(port:port);
      exit(0);
    }  
 }  
}

exit(0);

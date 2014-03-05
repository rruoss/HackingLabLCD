###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_38545.nasl 14 2013-10-27 12:33:37Z jan $
#
# Drupal Prior to 6.16 and 5.22 Multiple Security Vulnerabilities
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
tag_summary = "Drupal is prone to multiple vulnerabilities, including cross-site
scripting issues, a phishing issue, and a security-bypass issue.

An attacker may leverage these issues to execute arbitrary code in the
browser of an unsuspecting user in the context of the affected site,
steal cookie-based authentication credentials, bypass security
restrictions, or perform other attacks.

These issues affect the following:

Drupal 5.x prior to 5.22 Drupal 6.x prior to 6.16";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100523);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-09 22:32:06 +0100 (Tue, 09 Mar 2010)");
 script_bugtraq_id(38545);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Drupal Prior to 6.16 and 5.22 Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38545");
 script_xref(name : "URL" , value : "http://drupal.org");
 script_xref(name : "URL" , value : "http://drupal.org/node/731710");

 script_description(desc);
 script_summary("Determine if Drupal version is < 6.16 or < 5.22");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("drupal_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/drupal")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_in_range(version:vers, test_version:"5", test_version2:"5.21") ||
     version_in_range(version:vers, test_version:"6", test_version2:"6.15")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

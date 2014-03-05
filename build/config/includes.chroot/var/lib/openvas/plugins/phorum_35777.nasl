###############################################################################
# OpenVAS Vulnerability Test
# $Id: phorum_35777.nasl 15 2013-10-27 12:49:54Z jan $
#
# Phorum Multiple BBCode HTML Injection Vulnerabilities
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
tag_summary = "Phorum is prone to multiple HTML-injection vulnerabilities because it
fails to sufficiently sanitize user-supplied data.

Attacker-supplied HTML or JavaScript code could run in the context of
the affected site, potentially allowing the attacker to steal cookie-
based authentication credentials and to control how the site is
rendered to the user; other attacks are also possible.

Versions prior to Phorum 5.2.12a are vulnerable.";

tag_solution = "Vendor fixes are available. Please see the references for details.";

if (description)
{
 script_id(100248);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
 script_bugtraq_id(35777);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Phorum Multiple BBCode HTML Injection Vulnerabilities");

desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35777");
 script_xref(name : "URL" , value : "http://www.phorum.org/");
 script_xref(name : "URL" , value : "http://www.phorum.org/phorum5/read.php?64,139411");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/505186");

 script_description(desc);
 script_summary("Determine if Phorum Version is < 5.2.12a");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("phorum_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if(!version = get_kb_item(string("www/", port, "/phorum")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "5.2.12a")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

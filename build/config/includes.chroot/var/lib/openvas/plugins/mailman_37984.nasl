###############################################################################
# OpenVAS Vulnerability Test
# $Id: mailman_37984.nasl 14 2013-10-27 12:33:37Z jan $
#
# GNU Mailman Unspecified Privilege Escalation Vulnerability
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
tag_summary = "Mailman is prone to an unspecified privilege-escalation scripting
vulnerability.

 Few technical details are available at this time.

Local attackers may exploit this issue to obtain elevated privileges
and compromise a computer.

This issue is known to affect Mailman 2.0.2 and 2.0.4; other versions
may be vulnerable as well.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100475);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)");
 script_bugtraq_id(37984);
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"High");

 script_name("GNU Mailman Unspecified Privilege Escalation Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37984");
 script_xref(name : "URL" , value : "http://mailman.sourceforge.net/index.html");

 script_description(desc);
 script_summary("Determine if Mailman version is 2.0.2 or 2.0.4");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("mailman_detect.nasl");
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

if(!version = get_kb_item(string("www/", port, "/Mailman")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "2.0.2") ||
     version_is_equal(version: vers, test_version: "2.0.4")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

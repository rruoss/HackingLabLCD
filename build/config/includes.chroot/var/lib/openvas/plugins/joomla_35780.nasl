###############################################################################
# OpenVAS Vulnerability Test
# $Id: joomla_35780.nasl 15 2013-10-27 12:49:54Z jan $
#
# Joomla! Remote File Upload Vulnerability And Information Disclosure Weakness
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
tag_summary = "Joomla! is prone to a remote file-upload vulnerability and an information-
disclosure weakness.

Attackers can exploit these issues to disclosure sensitive
information, or upload arbitrary code and execute it in the context of
the webserver process. This may facilitate unauthorized access or
privilege escalation; other attacks are also possible.

Joomla! 1.5.x versions prior to 1.5.13 are vulnerable.";

tag_solution = "The vendor has released updates to address the issues. Please see the
references for more information.";

if (description)
{
 script_id(100333);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-03 12:50:27 +0100 (Tue, 03 Nov 2009)");
 script_bugtraq_id(35780);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Joomla! Remote File Upload Vulnerability And Information Disclosure Weakness");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35780");
 script_xref(name : "URL" , value : "http://developer.joomla.org/security/news/301-20090722-core-file-upload.html");
 script_xref(name : "URL" , value : "http://developer.joomla.org/security/news/302-20090722-core-missing-jexec-check.html");
 script_xref(name : "URL" , value : "http://www.joomla.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/505231");

 script_description(desc);
 script_summary("Determine if Joomla! version is 1.5 and < 1.5.13");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("joomla_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("joomla/installed");
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

if(!version = get_kb_item(string("www/", port, "/joomla")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_in_range(version: vers, test_version:"1.5", test_version2: "1.5.12")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);

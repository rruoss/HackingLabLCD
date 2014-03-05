###############################################################################
# OpenVAS Vulnerability Test
# $Id: xoops_37860.nasl 14 2013-10-27 12:33:37Z jan $
#
# XOOPS Arbitrary File Deletion and HTTP Header Injection Vulnerabilities
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
tag_summary = "XOOPS is prone to an HTTP-header-injection vulnerability and an arbitrary-file-
deletion vulnerability.

By inserting arbitrary headers into an HTTP response, attackers may be
able to launch various attacks, including cross-site request forgery,
cross-site scripting, and HTTP-request smuggling.

Successful file-deletion exploits may corrupt data and cause denial-of-
service conditions.

XOOPS 2.4.3 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100459);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
 script_bugtraq_id(37860);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("XOOPS Arbitrary File Deletion and HTTP Header Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37860");
 script_xref(name : "URL" , value : "http://www.codescanlabs.com/research/advisories/xoops-2-4-3-vulnerability/");
 script_xref(name : "URL" , value : "http://www.xoops.org");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/509034");

 script_description(desc);
 script_summary("Determine if if XOOPS version is <= 2.4.3");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_xoops_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/XOOPS")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers)) {

  if(version_is_less_equal(version: vers, test_version: "2.4.3")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

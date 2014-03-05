###############################################################################
# OpenVAS Vulnerability Test
# $Id: dokuwiki_multiple_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# DokuWiki Multiple Vulnerabilities
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
tag_summary = "DokuWiki is prone to an information-disclosure vulnerability and to
multiple security-bypass vulnerabilities.

Exploiting this issues may allow attackers to determine whether certain
files reside on the affected computer. Information obtained may lead
to further attacks. Unauthenticated attackers can leverage these
issues to change or delete wiki permissions.

This issue affects DokuWiki 2009-12-25; other versions may be
vulnerable as well.";


tag_solution = "Reports indicate that updates are available, but Symantec has not
confirmed this information. Please see the references and contact the
vendor for details.";

if (description)
{
 script_id(100451);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-18 11:34:48 +0100 (Mon, 18 Jan 2010)");
 script_cve_id("CVE-2010-0287");
 script_bugtraq_id(37821,37820);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("DokuWiki Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37821");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37820");
 script_xref(name : "URL" , value : "http://www.dokuwiki.org/");

 script_description(desc);
 script_summary("Determine if DokuWiki version is 2009-12-25");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_dokuwiki_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!version = get_kb_item(string("www/", port, "/DokuWiki")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2009.12.25b")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

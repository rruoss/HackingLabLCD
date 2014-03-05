###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_45210.nasl 72 2013-11-21 17:10:44Z mime $
#
# AWStats Unspecified 'LoadPlugin' Directory Traversal Vulnerability
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
tag_summary = "AWStats is prone to an unspecified directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input data.

The impact of this issue is currently unknown. We will update this BID
when more information emerges.

Versions prior to AWStats 7.0 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103041);
 script_version("$Revision: 72 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-21 18:10:44 +0100 (Thu, 21 Nov 2013) $");
 script_tag(name:"creation_date", value:"2011-01-25 13:20:03 +0100 (Tue, 25 Jan 2011)");
 script_bugtraq_id(45210);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-4369");

 script_name("AWStats Unspecified 'LoadPlugin' Directory Traversal Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "
";


 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed AWStats version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("awstats_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45210");
 script_xref(name : "URL" , value : "http://awstats.sourceforge.net/docs/awstats_changelog.txt");
 script_xref(name : "URL" , value : "http://sourceforge.net/tracker/?func=detail&amp;aid=2537928&amp;group_id=13764&amp;atid=113764");
 script_xref(name : "URL" , value : "http://awstats.sourceforge.net/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(vers = get_version_from_kb(port:port,app:"awstats")) {

  if(version_is_less(version: vers, test_version: "7.0")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: TorrentTrader_cve_2008_1173.nasl 15 2013-10-27 12:49:54Z jan $
#
# TorrentTrader 'msg' Parameter HTML Injection Vulnerability
#
# Authors
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
tag_summary = "TorrentTrader is prone to an HTML-injection vulnerability because it
  fails to adequately sanitize user-supplied input.

  Attacker-supplied HTML or JavaScript code could run in the context
  of the affected site, potentially allowing the attacker to steal
  cookie-based authentication credentials and to control how the site
  is rendered to the user; other attacks are also possible.

  TorrentTrader Classic 1.08 is affected; other versions may also be vulnerable.";

tag_solution = "This issue has been addressed in the revision 25/03/08 of Torrent Classic 1.08.
  Update to Torrent Classic 1.09.";

if (description)
{
 script_id(100181);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
 script_bugtraq_id(28082);
 script_cve_id("CVE-2008-1173");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("TorrentTrader 'msg' Parameter HTML Injection Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if TorrentTrader is vulnerable to HTML Injection");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("TorrentTrader_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/28082");
 script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?group_id=98584&amp;release_id=545219");
 script_xref(name : "URL" , value : "http://www.torrenttrader.org/index.php");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!version = get_kb_item(string("www/", port, "/torrenttrader")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "1.08")) {
    security_warning(port:port);
    exit(0);
  }  
}

exit(0);

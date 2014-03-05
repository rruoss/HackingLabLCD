###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpbb_45005.nasl 14 2013-10-27 12:33:37Z jan $
#
# phpBB 'includes/message_parser.php' HTML Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "phpBB is prone to an HTML-injection vulnerability because it fails to
properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials, control how the site is rendered to the user, or launch
other attacks.

Versions prior to phpBB 3.0.8 are vulnerable.";

tag_solution = "The vendor has released updates. Please contact the vendor for
details.";

if (description)
{
 script_id(100922);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-30 12:57:59 +0100 (Tue, 30 Nov 2010)");
 script_bugtraq_id(45005);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("phpBB 'includes/message_parser.php' HTML Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "
";


 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed phpBB is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45005");
 script_xref(name : "URL" , value : "http://www.phpbb.com/");
 script_xref(name : "URL" , value : "http://www.phpbb.com/support/documents.php?mode=changelog&amp;version=3#v307-PL1");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(vers = get_version_from_kb(port:port,app:"phpBB")) {

  if(version_is_less(version: vers, test_version: "3.0.8")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

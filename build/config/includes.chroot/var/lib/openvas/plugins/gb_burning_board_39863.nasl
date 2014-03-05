###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_burning_board_39863.nasl 14 2013-10-27 12:33:37Z jan $
#
# Woltlab Burning Board Arbitrary File Upload Vulnerability
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
tag_summary = "Woltlab Burning Board is prone to a vulnerability that lets attackers
upload arbitrary files because the application fails to adequately
sanitize user-supplied input.

An attacker can exploit this vulnerability to upload arbitrary code
and run it in the context of the webserver process. This may
facilitate unauthorized access or privilege escalation; other attacks
are also possible.

Burning Board Lite 1.0.2 is affected; other versions may also be
vulnerable.";


if (description)
{
 script_id(100629);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-06 13:19:12 +0200 (Thu, 06 May 2010)");
 script_bugtraq_id(39863);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Woltlab Burning Board Arbitrary File Upload Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39863");
 script_xref(name : "URL" , value : "http://www.woltlab.de/products/burning_board/index_en.php");

 script_description(desc);
 script_summary("Determine if remote Burning Board version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("secpod_woltlab_burning_board_detect.nasl");
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

if(vers = get_version_from_kb(port:port,app:"BurningBoard")) {

  if(version_is_equal(version: vers, test_version: "1.0.2 ")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);

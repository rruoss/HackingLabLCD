###############################################################################
# OpenVAS Vulnerability Test
# $Id: lighttpd_35097.nasl 15 2013-10-27 12:49:54Z jan $
#
# Lighttpd Trailing Slash Information Disclosure Vulnerability
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
tag_summary = "According to its version number, the remote version of Lighttpd is
  prone to an information-disclosure vulnerability.

  Attackers can exploit this issue to obtain sensitive information
  that may lead to further attacks.

  Lighttpd 1.4.23 is vulnerable; other versions may also be affected.";

tag_solution = "An update is available. Please see http://www.lighttpd.net
  for more information.";

if (description)
{
 script_id(100212);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-05-28 16:49:18 +0200 (Thu, 28 May 2009)");
 script_bugtraq_id(35097);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("Lighttpd Trailing Slash Information Disclosure Vulnerability");
 desc = "

 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine ithe version of Lighttpd");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35097");
 exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(get_kb_item("Services/www/" + port + "/embedded" ))exit(0);

banner = get_http_banner(port:port);
if (!banner)exit(0);
if(!egrep(pattern:"Server: lighttpd/[0-9.]+", string:banner) ) exit(0);

version = eregmatch(pattern: "Server: lighttpd/([0-9.]+)", string: banner);
if(!isnull(version[1])) {
  if( version_is_less_equal(version:version[1], test_version:"1.4.23") ) {

   security_warning(port:port);
   exit(0);

  }  
}

exit(0);

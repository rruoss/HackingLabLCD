###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manx_50839.nasl 13 2013-10-27 12:16:33Z jan $
#
# Manx Multiple Cross Site Scripting and Directory Traversal Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "Manx is prone to multiple cross-site scripting and directory-traversal
vulnerabilities because it fails to sufficiently sanitize user-
supplied input.

Exploiting these issues will allow an attacker to execute arbitrary
script code in the browser of an unsuspecting user in the context of
the affected site and to view arbitrary local files and directories
within the context of the webserver. This may let the attacker steal
cookie-based authentication credentials. Other harvested information
may aid in launching further attacks.

Manx 1.0.1 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103347);
 script_bugtraq_id(50839);
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("Manx Multiple Cross Site Scripting and Directory Traversal Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50839");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5058.php");
 script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2011-5060.php");
 script_xref(name : "URL" , value : "http://manx.jovascript.com/");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-11-30 11:09:07 +0100 (Wed, 30 Nov 2011)");
 script_description(desc);
 script_summary("Determine if installed Manx is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/manx");#,cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, '/admin/login.php/"onmouseover=alert("openvas-xss-test")>'); 

  if(http_vuln_check(port:port, url:url,pattern:'form action=""onmouseover=alert\\("openvas-xss-test"\\)>',check_header:TRUE)) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);
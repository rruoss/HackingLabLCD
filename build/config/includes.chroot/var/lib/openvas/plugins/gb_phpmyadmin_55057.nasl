###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_55057.nasl 12 2013-10-27 11:15:33Z jan $
#
# phpMyAdmin  'show_config_errors.php' Full Path Information Disclosure Vulnerability
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
tag_summary = "phpMyAdmin is prone to an information-disclosure vulnerability.

Attackers can exploit this issue to obtain sensitive information that
may lead to further attacks.

phpMyAdmin versions 3.5.x before 3.5.2.1 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103539";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(55057);
 script_cve_id("CVE-2012-4219");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_version ("$Revision: 12 $");

 script_name("phpMyAdmin 'show_config_errors.php' Full Path Information Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/55057");
 script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/index.php");

 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-17 11:08:07 +0200 (Fri, 17 Aug 2012)");
 script_description(desc);
 script_summary("Determine if phpMyAdmin is prone to full path information disclosure");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("phpMyAdmin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);
url = dir + '/show_config_errors.php';


if(http_vuln_check(port:port, url:url,pattern:'Call to undefined function.*/.*' + dir + '/show_config_errors.php')) {
     
  security_warning(port:port);
  exit(0);

}

exit(0);


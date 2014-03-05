###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_37032.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP 'symlink()' 'open_basedir' Restriction Bypass Vulnerability
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
tag_summary = "PHP is prone to an 'open_basedir' restriction-bypass vulnerability
because of a design error.

Successful exploits could allow an attacker to read and write files in
unauthorized locations.

This vulnerability would be an issue in shared-hosting configurations
where multiple users can create and execute arbitrary PHP script code.
In such cases, 'open_basedir' restrictions are expected to isolate
users from each other.

PHP 5.2.11 and 5.3.0 are vulnerable; other versions may also be
affected.";


if (description)
{
 script_id(100352);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-18 12:44:57 +0100 (Wed, 18 Nov 2009)");
 script_bugtraq_id(37032);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");

 script_name("PHP 'symlink()' 'open_basedir' Restriction Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37032");
 script_xref(name : "URL" , value : "http://securityreason.com/achievement_securityalert/70");
 script_xref(name : "URL" , value : "http://securityreason.com/achievement_exploitalert/14");
 script_xref(name : "URL" , value : "http://www.php.net/");

 script_description(desc);
 script_summary("Determine if php version is 5.2.11 or 5.3.0");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!vers = get_kb_item(string("www/", port, "/PHP")))exit(0);
if(!isnull(vers)) {

  if(version_is_equal(version: vers, test_version: "5.2.11") ||
     version_is_equal(version: vers, test_version: "5.3.0")) {
      security_warning(port:port);
      exit(0);
  }

}

exit(0);

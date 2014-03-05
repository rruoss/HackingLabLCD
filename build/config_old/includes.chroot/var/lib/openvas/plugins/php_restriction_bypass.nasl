###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_restriction_bypass.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHP multiple Restriction-Bypass Vulnerabilities
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
tag_summary = "PHP is prone to a 'safe_mode' and to a 'open_basedir'
restriction-bypass vulnerability. Successful exploits could allow an
attacker to access files in unauthorized locations or create files in
any writable directory and in unauthorized locations.

This vulnerability would be an issue in shared-hosting configurations
where multiple users can create and execute arbitrary PHP script code;
the 'safe_mode' and the 'open_basedir' restrictions are assumed to
isolate users from each other.

PHP 5.2.11 and 5.3.0 are vulnerable; other versions may also be
affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100281);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
 script_bugtraq_id(36555,36554);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("PHP multiple Restriction-Bypass Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36555");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/36554");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/ext/standard/file.c?view=log");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/standard/file.c?view=log");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/ext/posix/posix.c?view=log");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/posix/posix.c?view=log");
 script_xref(name : "URL" , value : "http://securityreason.com/securityalert/6601");
 script_xref(name : "URL" , value : "http://securityreason.com/securityalert/6600");
 script_xref(name : "URL" , value : "http://www.php.net");

 script_description(desc);
 script_summary("Determine if php version is 5.3.0 or 5.2.11");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("version_func.inc");
include("global_settings.inc");

## This nvt is prone to FP
if(report_paranoia < 2){
  exit(0);
}

phpPort = get_kb_item("Services/www");
if(!phpPort){
  exit(0);
}

phpVer = get_kb_item("www/" + phpPort + "/PHP");
if(!phpVer){
  exit(0);
}

if(version_is_equal(version:phpVer, test_version:"5.2.11") ||
   version_is_equal(version:phpVer, test_version:"5.3.0")) {

   security_hole(port:phpPort);
   exit(0);
}

exit(0);

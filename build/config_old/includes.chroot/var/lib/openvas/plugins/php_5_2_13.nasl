###############################################################################
# OpenVAS Vulnerability Test
# $Id: php_5_2_13.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP < 5.2.13 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
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
tag_summary = "The remote web server has installed a PHP Version which is prone to
Multiple Vulnerabilities.

1. A 'safe_mode' restriction-bypass vulnerability. Successful exploits
could allow an attacker to write session files in arbitrary
directions.

2. A 'safe_mode' restriction-bypass vulnerability. Successful exploits
could allow an attacker to access files in unauthorized locations or
create files in any writable directory.

3. An unspecified security vulnerability that affects LCG entropy.

PHP versions prior to 5.2.13 are affected.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100511);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-27 19:39:22 +0100 (Sat, 27 Feb 2010)");
 script_bugtraq_id(38182,38431,38430);
 script_cve_id("CVE-2010-1128", "CVE-2010-1129");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("PHP < 5.2.13 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 script_summary("Determine if installed PHP version is < 5.2.13");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38182");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38431");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38430");
 script_xref(name : "URL" , value : "http://securityreason.com/achievement_securityalert/82");
 script_xref(name : "URL" , value : "http://www.php.net/releases/5_2_13.php");
 script_xref(name : "URL" , value : "http://www.php.net");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_2/ext/session/session.c?r1=293036&amp;r2=294272");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/php/php-src/branches/PHP_5_3/ext/session/session.c?r1=293036&amp;r2=294272");
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

  if(version_is_less(version: vers, test_version: "5.2.13")) {
      security_hole(port:port);
      exit(0);
  }
}

exit(0);

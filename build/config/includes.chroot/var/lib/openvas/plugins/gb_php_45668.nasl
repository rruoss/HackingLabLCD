###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_45668.nasl 13 2013-10-27 12:16:33Z jan $
#
# PHP 'zend_strtod()' Function Floating-Point Value Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "PHP is prone to a remote denial-of-service vulnerability.

Successful attacks will cause applications written in PHP to hang,
creating a denial-of-service condition.

PHP 5.3.3 is vulnerable; other versions may also be affected.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_id(103020);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-01-10 13:28:19 +0100 (Mon, 10 Jan 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-4645");
 script_bugtraq_id(45668);

 script_name("PHP 'zend_strtod()' Function Floating-Point Value Denial of Service Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed php version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("php/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45668");
 script_xref(name : "URL" , value : "http://bugs.php.net/bug.php?id=53632");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc/?view=revision&amp;revision=307119");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc?view=revision&amp;revision=307095");
 script_xref(name : "URL" , value : "http://www.exploringbinary.com/php-hangs-on-numeric-value-2-2250738585072011e-308/");
 script_xref(name : "URL" , value : "http://www.php.net/");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if (!can_host_php(port:port)) exit(0);

if(!vers = get_kb_item(string("www/", port, "/PHP")))exit(0);

if(!isnull(vers)) {

  if(version_in_range(version: vers, test_version: "5.3", test_version2: "5.3.4") ||
     version_in_range(version: vers, test_version: "5.2", test_version2: "5.2.16")) {
      security_warning(port:port);
      exit(0);
  }


}

exit(0);

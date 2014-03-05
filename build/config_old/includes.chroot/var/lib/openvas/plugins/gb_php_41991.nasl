###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_41991.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Versions Prior to 5.3.3/5.2.14 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
tag_summary = "PHP is prone to multiple security vulnerabilities.

An attacker can exploit these issues to execute arbitrary code, crash
the affected application, gain access to sensitive information and
bypass security restrictions. Other attacks are also possible.

These issues affect the following:

PHP 5.3 (Prior to 5.3.3) PHP 5.2 (Prior to 5.2.14)";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100726);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
 script_bugtraq_id(41991);
 script_cve_id("CVE-2010-2531","CVE-2010-2484");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("PHP Versions Prior to 5.3.3/5.2.14 Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41991");
 script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.3.3");
 script_xref(name : "URL" , value : "http://www.php.net/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if the installed php version is vulnerable");
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
  if(vers =~ "^5\.2") {
    if(version_is_less(version: vers, test_version:"5.2.14")) {
      vuln = TRUE;
    } 
  } 
  else if(version =~ "^5\.3") {
    if(version_is_less(version: vers, test_version:"5.3.3")) {
      vuln = TRUE;
    }
  }

  if(vuln) {
    security_warning(port:port);
    exit(0);
  }

}

exit(0);

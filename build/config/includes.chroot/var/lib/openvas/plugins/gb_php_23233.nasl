###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_23233.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Str_Replace() Integer Overflow Vulnerability
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
tag_summary = "PHP is prone to an integer-overflow vulnerability because it
fails to ensure that integer values aren't overrun. Attackers
may exploit this issue to cause a buffer-overflow and corrupt
process memory.

Exploiting this issue may allow attackers to execute arbitrary machine
code in the context of the affected application. Failed exploit
attempts will likely result in a denial-of-service condition.

This issue affects versions prior to PHP 4.4.5 and 5.2.1.";

tag_solution = "The vendor released PHP 4.4.5 and 5.2.1 to address this issue. Please
see the references for more information.";

if (description)
{
 script_id(100594);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-21 13:10:07 +0200 (Wed, 21 Apr 2010)");
 script_bugtraq_id(23233);
 script_cve_id("CVE-2007-1885","CVE-2007-1886");

 script_name("PHP Str_Replace() Integer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/23233");
 script_xref(name : "URL" , value : "http://www8.itrc.hp.com/service/cki/docDisplay.do?docId=c01056506");
 script_xref(name : "URL" , value : "http://www.php-security.org/MOPB/MOPB-39-2007.html");
 script_xref(name : "URL" , value : "http://www.php.net/releases/4_4_5.php");
 script_xref(name : "URL" , value : "http://www.php.net/releases/5_2_1.php");
 script_xref(name : "URL" , value : "http://www.php.net/");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
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

if(vers = get_kb_item("www/" + port + "/PHP")) {

  if(vers =~ "^4\.4") {
    if(version_is_less(version: vers, test_version: "4.4.5")) {
        security_hole(port:port);
        exit(0);
    }
  }

  if(vers =~ "^5\.2") {
    if(version_is_less(version: vers, test_version: "5.2.1")) {
        security_hole(port:port);
        exit(0);
    }
  }
}

exit(0);
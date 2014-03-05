###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_30649.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Multiple Buffer Overflow Vulnerabilities
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
tag_summary = "PHP is prone to multiple buffer-overflow vulnerabilities.

Successful exploits may allow attackers to execute arbitrary code in
the context of applications using the vulnerable PHP functions. This
may result in a compromise of the underlying system. Failed attempts
may lead to a denial-of-service condition.

Versions prior to PHP 4.4.9 and PHP 5.2.8 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100583);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
 script_bugtraq_id(30649);
 script_cve_id("CVE-2008-3659","CVE-2008-3658");

 script_name("PHP Multiple Buffer Overflow Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/30649");
 script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.2.8");
 script_xref(name : "URL" , value : "http://www.php.net/archive/2008.php#id2008-08-07-1");
 script_xref(name : "URL" , value : "http://www.php.net/");
 script_xref(name : "URL" , value : "http://support.avaya.com/elmodocs2/security/ASA-2009-161.htm");

script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"risk_factor", value:"High");
script_description(desc);
script_summary("Determine if installed php version is vulnerable.");
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
    if(version_is_less(version: vers, test_version: "4.4.9")) {
        security_hole(port:port);
        exit(0);
    }
  }

  if(vers =~ "^5\.2") {
    if(version_is_less(version: vers, test_version: "5.2.8")) {
        security_hole(port:port);
        exit(0);
    }
  }
}

exit(0);

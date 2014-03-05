###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_31612.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP FastCGI Module File Extension Denial Of Service Vulnerabilities
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
tag_summary = "PHP is prone to a denial-of-service vulnerability because the
application fails to handle certain file requests.

Attackers can exploit this issue to crash the affected application,
denying service to legitimate users.

PHP 4.4 prior to 4.4.9 and PHP 5.2 through 5.2.6 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(100582);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-19 20:46:01 +0200 (Mon, 19 Apr 2010)");
 script_bugtraq_id(31612);
 script_cve_id("CVE-2008-3660");

 script_name("PHP FastCGI Module File Extension Denial Of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/31612");
 script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2008/08/08/2");
 script_xref(name : "URL" , value : "http://www.php.net/ChangeLog-5.php#5.2.8");
 script_xref(name : "URL" , value : "http://www.php.net");
 script_xref(name : "URL" , value : "http://support.avaya.com/elmodocs2/security/ASA-2009-161.htm");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed php version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_php_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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
        security_warning(port:port);
        exit(0);
    }
  }

  if(vers =~ "^5\.2") {
    if(version_is_less(version: vers, test_version: "5.2.8")) {
        security_warning(port:port);
        exit(0);
    }
  }
}

exit(0);

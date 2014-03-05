###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_39877.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP 'php_dechunk()' HTTP Chunked Encoding Integer Overflow Vulnerability
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
tag_summary = "PHP is prone to a remote integer-overflow vulnerability.

An attacker can exploit this issue to execute arbitrary code in the
context of the PHP process. Failed exploit attempts will result in a
denial-of-service condition.

PHP 5.3.0 through 5.3.2 are vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100617);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)");
 script_bugtraq_id(39877);
 script_cve_id("CVE-2010-1866");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");


 script_name("PHP 'php_dechunk()' HTTP Chunked Encoding Integer Overflow Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39877");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/02/mops-2010-003-php-dechunk-filter-signed-comparison-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://www.php.net");

 script_tag(name:"risk_factor", value:"High");
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
  if(version_in_range(version: vers, test_version: "5.3", test_version2: "5.3.2")) {
    security_hole(port:port);
    exit(0);
  }
}

exit(0);

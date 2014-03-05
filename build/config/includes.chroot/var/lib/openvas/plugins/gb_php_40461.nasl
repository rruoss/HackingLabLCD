###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_40461.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Mysqlnd Extension Information Disclosure and Multiple Buffer Overflow Vulnerabilities
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
tag_summary = "The PHP Mysqlnd extension is prone to an information-disclosure
vulnerability and multiple buffer-overflow vulnerabilities.

Successful exploits can allow attackers to obtain sensitive
information or to execute arbitrary code in the context of
applications using the vulnerable PHP functions. Failed attempts may
lead to a denial-of-service condition.

PHP 5.3 through 5.3.2 are vulnerable.";


if (description)
{
 script_id(100662);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-01 17:39:02 +0200 (Tue, 01 Jun 2010)");
 script_bugtraq_id(40461);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("PHP Mysqlnd Extension Information Disclosure and Multiple Buffer Overflow Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40461");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/31/mops-2010-056-php-php_mysqlnd_ok_read-information-leak-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/31/mops-2010-057-php-php_mysqlnd_rset_header_read-buffer-overflow-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/31/mops-2010-058-php-php_mysqlnd_read_error_from_line-buffer-overflow-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/31/mops-2010-059-php-php_mysqlnd_auth_write-stack-buffer-overflow-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://www.php.net/manual/en/book.mysqlnd.php");
 script_xref(name : "URL" , value : "http://www.php.net/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if remote php version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
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
  if(version_in_range(version: vers, test_version: "5.3", test_version2: "5.3.2")) { 
      security_hole(port:port);
      exit(0);
  }
}

exit(0);

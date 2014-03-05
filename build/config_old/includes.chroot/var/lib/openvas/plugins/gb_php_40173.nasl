###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_40173.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP 'ext/phar/stream.c' and 'ext/phar/dirstream.c' Multiple Format String Vulnerabilities
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
tag_summary = "PHP is prone to multiple format-string vulnerabilities because it
fails to properly sanitize user-supplied input before passing it as
the format specifier to a formatted-printing function.

Attackers can exploit these issues to run arbitrary code within the
context of the PHP process. This may allow them to bypass intended
security restrictions or gain elevated privileges.

PHP 5.3 through 5.3.2 are vulnerable.";

tag_solution = "Updates are available; please see the references for details.";

if (description)
{
 script_id(100643);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-17 12:46:01 +0200 (Mon, 17 May 2010)");
 script_bugtraq_id(40173);
 script_cve_id("CVE-2010-2094", "CVE-2010-2950");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

 script_name("PHP 'ext/phar/stream.c' and 'ext/phar/dirstream.c' Multiple Format String Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


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
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40173");
 script_xref(name : "URL" , value : "http://www.mail-archive.com/php-cvs@lists.php.net/msg46330.html");
 script_xref(name : "URL" , value : "http://svn.php.net/viewvc?view=revision&amp;revision=298667");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/14/mops-2010-024-php-phar_stream_flush-format-string-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/14/mops-2010-025-php-phar_wrapper_open_dir-format-string-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/14/mops-2010-026-php-phar_wrapper_unlink-format-string-vulnerability/index.html");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/14/mops-2010-027-php-phar_parse_url-format-string-vulnerabilities/index.html");
 script_xref(name : "URL" , value : "http://php-security.org/2010/05/14/mops-2010-028-php-phar_wrapper_open_url-format-string-vulnerabilities/index.html");
 script_xref(name : "URL" , value : "http://www.php.net");
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

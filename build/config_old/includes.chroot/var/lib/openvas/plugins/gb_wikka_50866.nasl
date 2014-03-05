###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wikka_50866.nasl 13 2013-10-27 12:16:33Z jan $
#
# WikkaWiki Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "WikkaWiki is prone to multiple security vulnerabilities, including:

1. An SQL injection vulnerability.
2. An arbitrary file upload vulnerability.
3. An arbitrary file deletion vulnerability.
4. An arbitrary file download vulnerability.
5. A PHP code injection vulnerability.

Attackers can exploit these issues to modify the logic of SQL queries;
upload, delete, or download arbitrary files; or inject and execute
arbitrary PHP code in the context of the affected application. Other
attacks may also be possible.

WikkaWiki 1.3.2 and prior versions are vulnerable.";


if (description)
{
 script_id(103350);
 script_bugtraq_id(50866);
 script_cve_id("CVE-2011-4448","CVE-2011-4449","CVE-2011-4450","CVE-2011-4451");
 script_version ("$Revision: 13 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("WikkaWiki Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50866");
 script_xref(name : "URL" , value : "http://wikkawiki.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520687");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-12-01 11:51:48 +0100 (Thu, 01 Dec 2011)");
 script_description(desc);
 script_summary("Determine if installed Wikka is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/wikka","/wikki",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/test/files.xml?action=download&file=/../../wikka.config.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"mysql_host", extra_check:make_list("mysql_database","mysql_user","mysql_password"))) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zenphoto_51916.nasl 12 2013-10-27 11:15:33Z jan $
#
# Zenphoto Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "Zenphoto is prone to multiple cross-site scripting vulnerabilities, an
SQL-injection vulnerability, and a PHP code-injection vulnerability.

An attacker can exploit the cross-site scripting issues to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site. This may allow the attacker to steal cookie-
based authentication credentials. The PHP code injection can be
exploited to inject and execute arbitrary malicious PHP code in the
context of the webserver process.

An attacker may be able to modify the logic of SQL queries. A
successful exploit may allow the attacker to compromise the
software, retrieve information, or modify data; other consequences
are possible as well.

ZENphoto 1.4.2 is vulnerable; other versions may also be affected";

tag_solution = "The vendor released updates to address these issues. Please see the
references for more information.";

if (description)
{
 script_id(103412);
 script_version ("$Revision: 12 $");
 script_bugtraq_id(51916);
 script_cve_id("CVE-2011-4448","CVE-2012-0993","CVE-2012-0995");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Zenphoto Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51916");
 script_xref(name : "URL" , value : "http://www.zenphoto.org/news/zenphoto-1.4.2.1");
 script_xref(name : "URL" , value : "http://www.zenphoto.org/");
 script_xref(name : "URL" , value : "https://www.htbridge.ch/advisory/HTB23070");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-09 12:57:10 +0100 (Thu, 09 Feb 2012)");
 script_description(desc);
 script_summary("Determine if installed Zenphoto is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/zenphoto",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/zp-core/admin.php?a=&quot;&gt;&lt;script&gt;alert(/openvas-xss-test/)&lt;/script&gt;"); 

  if(http_vuln_check(port:port, url:url,pattern:"<script>alert\(/openvas-xss-test/\)</script>",check_header:TRUE, extra_check:"zen-logo.png")) {
     
    security_hole(port:port);
    exit(0);

  }
}

exit(0);

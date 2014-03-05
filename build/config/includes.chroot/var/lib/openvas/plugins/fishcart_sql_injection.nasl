# OpenVAS Vulnerability Test
# $Id: fishcart_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: FishCart SQL injections
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
tag_summary = "FishCart, in use since January 1998, is a proven Open Source 
e-commerce system for products, services, online payment and
online donation management. Written in PHP4, FishCart has
been tested on Windows NT, Linux, and various Unix platforms.
FishCart presently supports the MySQL, PostgreSQL, Solid, Oracle and MSSQL.

FishCart contains multiple SQL injection vulnerabilities in the program
that can be exploited to modify/delete/insert entries into the database.

In addition, the program suffers from cross site scripting vulnerabilities.";

# Multiple SQL injections and XSS in FishCart 3.1
# "Diabolic Crab" <dcrab@hackerscenter.com>
# 2005-05-03 23:07

if(description)
{
 script_id(18191);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2005-1486", "CVE-2005-1487");
 script_bugtraq_id(13499);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 name = "FishCart SQL injections";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Checks for the presence of an SQL injection in upstnt.asp";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/upstnt.php?zid=1&lid=1&cartid='"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);
 if("Invalid SQL: select sku,qty from mwestoline where orderid='''" >< r)
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

# OpenVAS Vulnerability Test
# $Id: b2evolution_net_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: b2Evolution title SQL Injection
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
tag_summary = "The remote host is running b2evolution, a blog engine written in PHP.

There is an SQL injection vulnerability in the remote version of this software
which may allow an attacker to execute arbitrary SQL statements against the
remote database by providing a malformed value to the 'title' argument
of index.php.";

tag_solution = "None at this time";

# b2Evolution Security Flaws - SQL Injection - Forgot to incldue a solution.
# From: r0ut3r <shady.underground@gmail.com>
# Date: 2005-01-06 10:05

if(description)
{
 script_id(16121);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_bugtraq_id(12179);
 
 name = "b2Evolution title SQL Injection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
script_xref(name : "URL" , value : "http://osvdb.org/12717");
script_xref(name : "URL" , value : "http://secunia.com/advisories/13718");
script_xref(name : "URL" , value : "http://securitytracker.com/id?1012797");
script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/18762");

 script_description(desc);
 
 summary = "Checks for the presence of an SQL injection in title parameter";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php?blog=1&title='&more=1&c=1&tb=1&pb=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if("SELECT DISTINCT ID, post_author, post_issue_date" >< r)
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}


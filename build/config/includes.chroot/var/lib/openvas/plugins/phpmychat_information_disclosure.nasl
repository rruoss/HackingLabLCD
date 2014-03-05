# OpenVAS Vulnerability Test
# $Id: phpmychat_information_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: phpMyChat Information Disclosure
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
tag_summary = "phpMyChat is an easy-to-install, easy-to-use multi-room
chat based on PHP and a database, supporting MySQL,
PostgreSQL, and ODBC.

This set of script may allow an attacker to cause an information
disclosre vulnerability allowing an attacker to cause the
program to reveal the SQL username and password, the phpMyChat's
administrative password, and other sensitive information.";

if(description)
{
 script_id(16056);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "phpMyChat Information Disclosure";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 
 summary = "Checks for the presence of an Information Disclosure in phpMyChat";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_xref(name : "URL" , value : "http://www.securiteam.com/unixfocus/6D00S0KC0S.html");
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 if (debug) { display("loc: ", loc, "\n"); }
 req = http_get(item:string(loc, "/setup.php3?next=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if(("C_DB_NAME" >< r) || ("C_DB_USER" >< r) || ("C_DB_PASS" >< r))
 {
 	security_hole(port);
	exit(0);
 }
}

dirs = make_list(cgi_dirs(), "/forum", "/forum/chat", "/chat", "/chat/chat", ""); # The /chat/chat isn't a mistake

foreach dir (dirs)
{
 check(loc:dir);
}


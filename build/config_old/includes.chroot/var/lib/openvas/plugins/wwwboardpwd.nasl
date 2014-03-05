# OpenVAS Vulnerability Test
# $Id: wwwboardpwd.nasl 17 2013-10-27 14:01:43Z jan $
# Description: wwwboard passwd.txt
#
# Authors:
# Jonathan Provencher <druid@balistik.net>
#
# Copyright:
# Copyright (C) 1999 Jonathan Provencher
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
tag_summary = "The remote web server contains a CGI application that is prone to
information disclosure. 

Description :

The remote host is running WWWBoard, a bulletin board system written
by Matt Wright.

This board system comes with a password file (passwd.txt) installed
next to the file 'wwwboard.html'.  An attacker may obtain the content
of this file and decode the password to modify the remote www board.";

tag_solution = "Configure the wwwadmin.pl script to change the name and location of
'passwd.txt'.";

if(description)
{
 script_id(10321);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(649, 12453);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-1999-0953");
 
 name = "wwwboard passwd.txt";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks for the presence of /wwwboard/passwd.txt";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 1999 Jonathan Provencher");

 family = "Web application abuses";
 script_family(family);
 	

 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/1998_3/0746.html");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/1999-q3/0993.html");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

foreach dir(cgi_dirs())
{
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/wwwboard.html"), bodyonly:TRUE);
 if (res == NULL )exit(0);
 if ( "wwwboard.pl" >< res )
 {
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/passwd.txt"), bodyonly:TRUE);
 if ( strlen(res) && egrep(pattern:"^[A-Za-z0-9]*:[a-zA-Z0-9-_.]$", string:res))
	{
	 security_hole(port);
	 exit(0);
	}
 }
}


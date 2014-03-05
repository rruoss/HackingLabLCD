# OpenVAS Vulnerability Test
# $Id: fusion_sbx_bypass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Fusion SBX Password Bypass and Command Execution
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
tag_summary = "The remote host is running Fusion SBX, a guest book written in PHP.

A vulnerability in the remote version of this software allows remote 
attackers to modify the product's settings without knowing the
administrator password, in addition by injecting arbitrary
PHP code to one of the board's settings a remote attacker
is able to cause the program to execute arbitrary code.";

tag_solution = "None at this time";

# "Dave" <dave@kidindustries.net>
# 2005-05-05 07:03
# Fusion SBX 1.2 password bypass and remote command execution

if(description)
{
 script_id(18210);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(13575);
 script_cve_id("CVE-2005-1596");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 
 name = "Fusion SBX Password Bypass and Command Execution";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for the presence of a Fusion SBX Password Bypass";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
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
 req = string("POST ", loc, "/admin/index.php HTTP/1.1\r\n",
 "Host: ", get_host_name(), "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.5) Gecko/20041207 Firefox/1.0\r\n",
 "Content-Type: application/x-www-form-urlencoded\r\n",
 "Content-Length: 11\r\n",
 "\r\n",
 "is_logged=1");
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("data/data.db" >< r && "data/ipban.db" >< r)
 {
  security_hole(port:port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() ) check(loc:dir);


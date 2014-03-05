# OpenVAS Vulnerability Test
# $Id: zyxel_pwd.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Default password router Zyxel
#
# Authors:
# Giovanni Fiaschi <giovaf@sysoft.it>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID.  
#
# Copyright:
# Copyright (C) 2001 Giovanni Fiaschi
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
tag_summary = "The remote host is a Zyxel router with its default password set.

An attacker could telnet to it and reconfigure it to lock the owner out and to 
prevent him from using his Internet connection, or create a dial-in user to 
connect directly to the LAN attached to it.";

tag_solution = "Telnet to this router and set a password immediately.";

if(description)
{
   script_id(10714);
   script_version("$Revision: 17 $");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
   script_bugtraq_id(3161);
   script_tag(name:"cvss_base", value:"10.0");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
   script_tag(name:"risk_factor", value:"Critical");
   
   script_cve_id("CVE-1999-0571");
   
   name = "Default password router Zyxel";
   script_name(name);
 
   desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;


   script_description(desc);
 
   summary = "Logs into the router Zyxel";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2001 Giovanni Fiaschi");
   script_family("Privilege escalation");
   script_require_ports(23);
 
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
   }
   exit(0);
}

port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:8192, min:1);
   s = string("1234\r\n");
   send(socket:soc, data:s);
   r = recv(socket:soc, length:8192, min:1);
   close(soc);
   if("ZyXEL" >< r)security_hole(port);
 }
}

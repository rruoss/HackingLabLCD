# OpenVAS Vulnerability Test
# $Id: nortel_pwdless1.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Nortel Networks passwordless router (manager level)
#
# Authors:
# Victor Kirhenshtein <sauros@iname.com>
# Based on cisco_675.nasl by Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2000 Victor Kirhenshtein
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
tag_summary = "The remote Nortel Networks (former Bay Networks) router has
no password for the manager account. 

An attacker could telnet to the router and reconfigure it to lock 
you out of it. This could prevent you from using your Internet 
connection.";

tag_solution = "telnet to this router and set a password
immediately.";

if(description)
{
   script_id(10528);
   script_version("$Revision: 17 $");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
   script_tag(name:"cvss_base", value:"7.8");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
   script_tag(name:"risk_factor", value:"High");
   name = "Nortel Networks passwordless router (manager level)";
   script_name(name);
 
   desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;
   script_description(desc);
 
   summary = "Logs into the remote Nortel Networks (Bay Networks) router";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2000 Victor Kirhenshtein");
   script_family("General");
   script_require_ports(23);
 
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
   }
   exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 23;
if(get_port_state(port))
{
   buf = get_telnet_banner(port:port);
   if ( ! buf || "Bay Networks" >!< buf ) exit(0);
   soc = open_sock_tcp(port);
   if(soc)
   {
      buf = telnet_negotiate(socket:soc);
      if("Bay Networks" >< buf)
      {
         if ("Login:" >< buf)
         {
            data = string("Manager\r\n");
            send(socket:soc, data:data);
            buf2 = recv(socket:soc, length:1024);
            if("$" >< buf2) security_hole(port);
         }
      }
      close(soc);
   }
}

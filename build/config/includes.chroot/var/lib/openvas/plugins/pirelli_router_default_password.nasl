# OpenVAS Vulnerability Test
# $Id: pirelli_router_default_password.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Default password router Pirelli AGE mB
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 1999 Anonymous
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
tag_summary = "The remote host is a Pirelli AGE mB (microBusiness) router with its 
default password set (admin/microbusiness).

An attacker could telnet to it and reconfigure it to lock the owner out 
and to prevent him from using his Internet connection, and do bad things.";

tag_solution = "Telnet to this router and set a password immediately.";

if(description)
{
   script_id(12641);
   script_version("$Revision: 17 $");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
   script_tag(name:"cvss_base", value:"7.5");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
   script_tag(name:"risk_factor", value:"High");
   script_cve_id("CVE-1999-0502");

 
   name = "Default password router Pirelli AGE mB";
   script_name(name);
 
   desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;

   script_description(desc);
 
   summary = "Logs into the router Pirelli AGE mB";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("Copyright (C) 1999 Anonymous");
   script_family("General");
   script_require_ports(23);
 
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
   }
   exit(0);
}

include("default_account.inc");
include("telnet_func.inc");

port = 23;
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if ( ! banner || "USER:" >!< banner ) exit(0);

 #First try as Admin
soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv_until(socket:soc, pattern:"(USER:|ogin:)");
   if ( "USER:" >!< r ) exit(0); 
   s = string("admin\r\nmicrobusiness\r\n");
   send(socket:soc, data:s);
   r = recv_until(socket:soc, pattern:"Configuration");
   close(soc);
   if( r && "Configuration" >< r )
   {
     security_hole(port);
     exit(0);
   }
 }
 #Second try as User (reopen soc beacause wrong pass disconnect)
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv_until(socket:soc, pattern:"(USER:|ogin:)");
   if ( "USER:" >!< r ) exit(0);
   s = string("user\r\npassword\r\n");
   send(socket:soc, data:s);
   r = recv_until(socket:soc, pattern:"Configuration");
   close(soc);
   if( r && "Configuration" >< r )
   {
     security_hole(port);
   }
 }
}


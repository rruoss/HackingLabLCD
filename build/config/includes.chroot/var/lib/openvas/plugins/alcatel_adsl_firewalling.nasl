# OpenVAS Vulnerability Test
# $Id: alcatel_adsl_firewalling.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Alcatel ADSL modem with firewalling off
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
tag_summary = "On the Alcatel Speed Touch Pro ADSL modem, a protection mechanism 
feature is available to ensure that nobody can gain remote access 
to the modem (via the WAN/DSL interface). This mechanism guarantees 
that nobody from outside your network can access the modem and 
change its settings.

The protection is currently not activated on your system.";

tag_solution = "Telnet to this modem and adjust the security
settings as follows:
=> ip config firewalling on
=> config save

More information : http://www.alcatel.com/consumer/dsl/security.htm";


if(description)
{
   script_id(10760);
   script_version("$Revision: 17 $");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
   script_cve_id("CVE-2001-1424", "CVE-2001-1425");
   script_bugtraq_id(2568);
   script_tag(name:"cvss_base", value:"7.5");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
   script_tag(name:"risk_factor", value:"High");
   name = "Alcatel ADSL modem with firewalling off";
   script_name(name);
 
   desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;


   script_description(desc);
 
   summary = "Checks Alcatel ADSL modem protection";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
   script_family("General");
   script_require_ports(23);
 
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
   }
   exit(0);
}

include('global_settings.inc');

if ( ! thorough_tests && ! ereg(pattern:"^10\.0\.0\..*", string:get_host_ip())) exit(0);

port = 23; # alcatel's ADSL modem telnet module can't bind to something else

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:160);
   if("User : " >< r)
   {
     send(socket:soc, data:string("\r\n"));
     r = recv(socket:soc, length:2048);
     if("ALCATEL ADSL" >< r)
     {
       s = string("ip config\r\n");
       send(socket:soc, data:s);
       r = recv(socket:soc, length:2048);
       if("Firewalling off" >< r)security_hole(port);
     }
   }
   close(soc);
 }
}

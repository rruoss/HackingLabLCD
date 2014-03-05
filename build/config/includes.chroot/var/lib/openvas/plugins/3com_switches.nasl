# OpenVAS Vulnerability Test
# $Id: 3com_switches.nasl 17 2013-10-27 14:01:43Z jan $
# Description: 3Com Superstack 3 switch with default password
#
# Authors:
# Patrik Karlsson <patrik.karlsson@ixsecurity.com>
# Enhancements by Tomi Hanninen
#
# Copyright:
# Copyright (C) 2001 Patrik Karlsson
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
tag_summary = "The 3Com Superstack 3 switch has the default passwords set.

The attacker could use these default passwords to gain remote
access to your switch and then reconfigure the switch. These
passwords could also be potentially used to gain sensitive
information about your network from the switch.";

tag_solution = "Telnet to this switch and change the default passwords
immediately.";

if(description)
{
    script_id(10747);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"Medium");
    script_cve_id("CVE-1999-0508");
   name = "3Com Superstack 3 switch with default password";
   script_name(name);
 
   desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;

   script_description(desc);
 
   summary = "Logs into 3Com Superstack 3 switches with default passwords";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2001 Patrik Karlsson");
   script_family("Privilege escalation");
   script_require_ports(23);

   script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value: "no");
 
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
   exit(0);
}

include('telnet_func.inc');
include("default_credentials.inc");

port = 23; # the port can't be changed

banner = get_telnet_banner(port:port);
if ( "Login : " >!< banner ) exit(0);

bfound = 0;

res = string("Standard passwords were found on this 3Com Superstack switch.\n");
res = res + string("The passwords found are:\n\n");

if(get_port_state(port))
{

  p = script_get_preference("Use complete password list (not only vendor specific passwords)");

  if("yes" >< p) {
    clist = try();
  } else {
    clist = try(vendor:"3com");
  } 

  foreach credential (clist) 
  {

     user_pass = split(credential, sep:";",keep:FALSE);
     if(isnull(user_pass[0]) || isnull(user_pass[1]))continue;

     user = chomp(user_pass[0]);
     pass = chomp(user_pass[1]);

     if(tolower(pass) == "none")pass = "";

     soc = open_sock_tcp(port);
     if(soc)
     {
        r = recv(socket:soc, length:160);
        if("Login: " >< r)
        {
	    tmp = string(user, "\r\n");
	    send(socket:soc, data:tmp);
	    r = recv_line(socket:soc, length:2048);
            tmp = string(pass, "\r\n");
	    send(socket:soc, data:tmp);
	    r = recv(socket:soc, length:4096);

	    if ( "logout" >< r )
	    {
		bfound = 1;
		res = string(res, user, ":", pass, "\n");
     	    }

        }
   
      close(soc);

  }

 }

 res = string(res, "\nSolution : Telnet to this switch immediately and ",
 		  "change the passwords above.\n");

 if ( bfound == 1 )
 {
      security_warning(port:23, data:res);
 }
}

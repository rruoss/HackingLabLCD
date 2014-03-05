# OpenVAS Vulnerability Test
# $Id: avaya_switches.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Avaya P330 Stackable Switch found with default password
#
# Authors:
# Charles Thier <cthier@thethiers.net>
#
# Copyright:
# Copyright (C) 2005 Charles Thier
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
tag_summary = "The remote host appears to be an Avaya P330 Stackable Switch with
its default password set.

The attacker could use this default password to gain remote access
to your switch.  This password could also be potentially used to
gain other sensitive information about your network from the switch.";

tag_solution = "Telnet to this switch and change the default password.";

if(description)
{
    script_id(17638);
    script_version("$Revision: 17 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"Medium");
    script_cve_id("CVE-1999-0508");
    name = "Avaya P330 Stackable Switch found with default password";
    script_name(name);
 
   desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;

   script_description(desc);
 
   summary = "Logs into Avaya switches with default password";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2005 Charles Thier");
   script_family("Privilege escalation");
   script_require_ports(23);

   script_add_preference(name:"Use complete password list (not only vendor specific passwords)", type:"checkbox", value: "no");

    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
   exit(0);
}


#
# The script code starts here
#

include("telnet_func.inc");
include("default_credentials.inc");


port = 23;
if(get_port_state(port))
{
	tnb = get_telnet_banner(port);
	if ( ! tnb ) exit(0);
        if ("Welcome to P330" >< tnb)
        {

	  p = script_get_preference("Use complete password list (not only vendor specific passwords)");

	  if("yes" >< p) {
            clist = try();
	  } else {  
 	    clist = try(vendor:"avaya");
	  }   

	  foreach credential (clist) {

	    user_pass = split(credential, sep:";",keep:FALSE);
            if(isnull(user_pass[0]) || isnull(user_pass[1]))continue;

	    user = chomp(user_pass[0]);
	    pass = chomp(user_pass[1]);

	    if(tolower(pass) == "none")pass = "";

                soc = open_sock_tcp(port);
                if(soc)
                {
                        answer = recv(socket:soc, length:4096);
                        if("ogin:" >< answer)
                        {
                                send(socket:soc,data:string(user,"\r\n"));
                                answer = recv(socket:soc, length:4096);
                                send(socket:soc, data:string(pass,"\r\n"));
                                answer = recv(socket:soc, length:4096);
                                if("Password accepted" >< answer)
                                {
                                        security_warning(port:23);
                                }
                        }
                close(soc);
                }
           }
        }
}


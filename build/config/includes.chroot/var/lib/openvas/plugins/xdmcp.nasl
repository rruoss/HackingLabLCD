# OpenVAS Vulnerability Test
# $Id: xdmcp.nasl 17 2013-10-27 14:01:43Z jan $
# Description: X Display Manager Control Protocol (XDMCP)
#
# Authors:
# Pasi Eronen <pasi.eronen@nixu.com>
#
# Copyright:
# Copyright (C) 2002 Pasi Eronen
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
tag_solution = "Disable XDMCP";
tag_summary = "The remote host is running XDMCP.

This protocol is used to provide X display connections for X terminals. 
XDMCP is completely insecure, since the traffic and passwords are not 
encrypted. 

An attacker may use this flaw to capture all the keystrokes of the users 
using this host through their X terminal, including passwords.

Also XDMCP is an additional login mechanism that you may not have been 
aware was enabled, or may not be monitoring failed logins on.";

if(description)
{
 script_id(10891);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "X Display Manager Control Protocol (XDMCP)";
 script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "

 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks if XDM has XDMCP protocol enabled";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Pasi Eronen");
 family = "Useless services";
 script_family(family);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

# this magic info request packet
req = raw_string(0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00);

if(!get_udp_port_state(177))exit(0);

soc = open_sock_udp(177);

if(soc)
{
        send(socket:soc, data:req);
        result  = recv(socket:soc, length:1000);
        if (result && (result[0] == raw_string(0x00)) &&
            (result[1] == raw_string(0x01)) &&
            (result[2] == raw_string(0x00))) {
                security_warning(port:177, protocol:"udp");
        }
}

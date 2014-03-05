# OpenVAS Vulnerability Test
# $Id: port_shell_execution.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Shell Command Execution Vulnerability
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecurITeam
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
tag_summary = "The remote port seems to be running some form of shell script,
with some provided user input. The input is not stripped for such meta 
characters as ` ' ; , etc. This would allow a remote attacker to
execute arbitrary code.";

tag_solution = "Make sure all meta characters are filtered out, or close the port
for access from untrusted networks";

if(description)
{
 script_id(10879);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "Shell Command Execution Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Checks for the filtering of dangerous meta characters from network binded scripts";
 
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); # Potentially destructive
 
 script_copyright("This script is Copyright (C) 2001 SecurITeam");

 family = "Gain a shell remotely";

 script_family(family);
 script_require_keys("Settings/ThoroughTests");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');
if ( ! thorough_tests ) exit(0);

function test_port(port, command)
{
  soc = open_sock_tcp(port);
  if(soc)
  {
   data = string("`", command, "` #\r\n");
   send(socket:soc, data:data);
 
   buf = recv(socket:soc, length:65535, min:1);
   looking_for = string("uid=");

   if (looking_for >< buf)
   {
    security_hole(port);
    return(1);
   }

   close(soc);
  }
 }


function test_for_backtick(port)
{
  soc = open_sock_tcp(port);
  if(soc)
  {
   data = string("`\r\n");
   send(socket:soc, data:data);

   buf = recv(socket:soc, length:65535, min:1);

   looking_for = string("sh: unexpected EOF while looking for ");
   looking_for_2 = raw_string(0x60, 0x60, 0x27);

   looking_for = string(looking_for, looking_for_2);
   if (looking_for >< buf)
   {
    security_hole(port);
    return(1);
   }

   close(soc);
  }
}

ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);

foreach port (keys(ports))
{
 port = int(port - "Ports/tcp/");
 if(test_for_backtick(port:port))break;
 if(test_port(port:port, command:"/bin/id"))break;
 test_port(port:port, command:"/usr/bin/id");
}



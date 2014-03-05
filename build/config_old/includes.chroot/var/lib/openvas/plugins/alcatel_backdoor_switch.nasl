# OpenVAS Vulnerability Test
# $Id: alcatel_backdoor_switch.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Alcatel OmniSwitch 7700/7800 switches backdoor
#
# Authors:
# deepquest <deepquest@code511.com>
# Modifications by rd:
# -  added ref: http://www.cert.org/advisories/CA-2002-32.html
# -  removed leftovers in the code (send(raw_string(0, 0))
# -  added the use of telnet_init()
# -  replaced open_sock_udp by open_sock_tcp()
# -  added script id
# -  attributed copyright properly to deepquest
# -  merged some ideas from Georges Dagousset <georges.dagousset@alert4web.com> 
#    who wrote a duplicate of this script
#
# Copyright:
# Copyright (C) 2002 deepquest
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
# This script was written by deepquest <deepquest@code511.com>
# Modifications by rd:
# -  added ref: http://www.cert.org/advisories/CA-2002-32.html
# -  removed leftovers in the code (send(raw_string(0, 0))
# -  added the use of telnet_init()
# -  replaced open_sock_udp by open_sock_tcp()
# -  added script id
# -  attributed copyright properly to deepquest
# -  merged some ideas from Georges Dagousset <georges.dagousset@alert4web.com> 
#    who wrote a duplicate of this script

include("revisions-lib.inc");
tag_summary = "The remote host seems to be a backdoored
Alcatel OmniSwitch 7700/7800.

An attacker can gain full access to any device
running AOS version 5.1.1, which can result in,
but is not limited to, unauthorized access,
unauthorized monitoring, information leakage,
or denial of service.";

tag_solution = "Block access to port 6778/TCP or update to
AOS 5.1.1.R02 or AOS 5.1.1.R03.";

if(description)
{
 script_id(11170);
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(6220);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2002-1272");

 name = "Alcatel OmniSwitch 7700/7800 switches backdoor";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "

";

 script_description(desc);
 
 summary = "Checks for the presence of backdoor in Alcatel  7700/7800 switches ";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (c) 2002 deepquest");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service.nasl");
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-2002-32.html");
 exit(0);
}


include("telnet_func.inc");
include("misc_func.inc");

port = 6778;
p = known_service(port:port);
if(p && p != "telnet" && p != "aos")exit(0);



if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = get_telnet_banner(port:port);
 if(data)
  {
  security_note(port:port,data:string("The banner:\n",data,"\nshould be reported to openvas-plugins@wald.intevation.org\n"));
  security_hole(port);
  register_service(port: port, proto: "aos");
  }
 }
}

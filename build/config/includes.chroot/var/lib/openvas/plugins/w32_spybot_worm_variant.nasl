# OpenVAS Vulnerability Test
# $Id: w32_spybot_worm_variant.nasl 17 2013-10-27 14:01:43Z jan $
# Description: w32.spybot.fcd worm infection
#
# Authors:
# Jorge E Rodriguez <KPMG>
# 	- check the system for infected w32.spybot.fbg
#	- script id
#	- cve id
#
# Copyright:
# Copyright (C) 2004 jorge rodriguez
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
tag_summary = "The remote system is infected with a variant of the worm w32.spybot.fcd. 

Infected systems will scan systems that are vulnerable in the same subnet
in order to attempt to spread.

This worm also tries to do DDoS against targets in the Internet.";

tag_solution = "ensure all MS patches are applied as well as the latest AV
definitions.";

if(description)
{
 script_id(15520);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 
 name = "w32.spybot.fcd worm infection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "

";
 script_description(desc);
 
 summary = "Detects if w32.spybot.fcd is installed on the remote host";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 jorge rodriguez");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service1.nasl", "os_fingerprint.nasl");
 script_require_ports(113);
 script_exclude_keys('fake_identd/113');
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://securityresponse.symantec.com/avcenter/venc/data/w32.spybot.fcd.html");
 exit(0);
}

#
# The script code starts here
#
include('misc_func.inc');
include('host_details.inc');

if (host_runs("Windows") != "yes") exit(0);

if (get_kb_item('fake_identd/113')) exit(0);

if(get_port_state(113))
{
 soc = open_sock_tcp(113);
 if(soc)
 {
  req = string("GET\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  if(" : USERID : UNIX :" >< r) {
	if ( "GET : USERID : UNIX :" >< r ) exit(0);
	security_hole(113);
	if (service_is_unknown(port: 113))
	  register_service(port: port, proto: 'fake-identd');
	set_kb_item(name: 'fake_identd/113', value: TRUE);
	}
  close(soc);
 }
}

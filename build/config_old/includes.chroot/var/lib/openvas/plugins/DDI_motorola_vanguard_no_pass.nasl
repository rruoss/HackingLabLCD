# OpenVAS Vulnerability Test
# $Id: DDI_motorola_vanguard_no_pass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Motorola Vanguard with No Password
#
# Authors:
# Geoff Humes <geoff.humes@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense
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
tag_summary = "This device is a Motorola Vanguard router and has 
no password set. An attacker can reconfigure 
this device without providing any authentication.";

tag_solution = "Please set a strong password for this device.";

if(description)
{
	script_id(11203);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"Medium");
	script_cve_id("CVE-1999-0508");
	name = "Motorola Vanguard with No Password";
	script_name(name);
 
	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

	script_description(desc);
 
	summary = "Attempts to log into Vanguards.";
	script_summary(summary);
 
	script_category(ACT_GATHER_INFO);
 
	script_copyright("This script is Copyright (C) 2003 Digital Defense");
	family = "General";
	script_family(family);
	script_require_ports(23);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}

include('telnet_func.inc');

function greprecv(socket, pattern)
{
 buffer = "";
 cnt = 0;
 while(1)
 {
  _r = recv_line(socket:soc, length:4096);
  if(strlen(_r) == 0)return(0);
  buffer = string(buffer, _r);
  if(ereg(pattern:pattern, string:_r))return(buffer);
  cnt = cnt + 1;
  if(cnt > 1024)return(0);
 }
}

#
# The script code starts here
#
port = 23;


if(get_port_state(port))
{
	banner = get_telnet_banner(port:port);
	if ( ! banner || "OK" >!< banner ) exit(0);

	soc = open_sock_tcp(port);
	if(soc)
	{
		buf = greprecv(socket:soc, pattern:".*OK.*");
		if(!buf)exit(0);
		send(socket:soc, data:string("atds0\r\n"));
		buf = greprecv(socket:soc, pattern:".*Password.*");
		if(!buf)exit(0);
		send(socket:soc, data:string("\r\n"));
		buf = greprecv(socket:soc, pattern:".*Logout.*");
		if(buf)security_warning(port);
		close(soc);
	}
}
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_jet_direct_unauthenticated_access.nasl 12 2013-10-27 11:15:33Z jan $
#
# HP LaserJet Printers Unauthenticated Access
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "HP Laserjet printers with JetDirect cards, when configured with
TCP/IP, can be configured without a password, which allows remote
attackers to connect to the printer and change its IP address or
disable logging.";

tag_solution = "Connect to this printer via telnet and set a password by executing
the 'passwd' command.";

if (description)
{
 script_id(103390);
 script_cve_id("CVE-1999-1061");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");

 script_name("HP LaserJet Printers Unauthenticated Access");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-1061");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-01-13 10:43:06 +0100 (Fri, 13 Jan 2012)");
 script_description(desc);
 script_summary("Determine if HP LaserJet Printer allows unauthenticated Access");
 script_category(ACT_ATTACK);
 script_family("General");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("telnetserver_detect_type_nd_version.nasl");
 script_require_ports(23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include('telnet_func.inc');

port = 23;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

buf = telnet_negotiate(socket:soc);
if("HP JetDirect" >!< buf)exit(0);

send(socket:soc, data:string("/\r\n"));
buf = recv(socket:soc, length: 1024);

close(soc);

if("JetDirect Telnet Configuration" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(0);

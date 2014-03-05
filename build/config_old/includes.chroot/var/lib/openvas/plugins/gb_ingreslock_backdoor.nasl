###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ingreslock_backdoor.nasl 12 2013-10-27 11:15:33Z jan $
#
# Possible Backdoor: Ingreslock
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
tag_summary = "A backdoor is installed on the remote host

Attackers can exploit this issue to execute arbitrary commands in the
context of the application. Successful attacks will compromise the
affected isystem.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103549";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Possible Backdoor: Ingreslock");

desc = "
 Summary:
 " + tag_summary;

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-22 16:21:38 +0200 (Wed, 22 Aug 2012)");
 script_description(desc);
 script_summary("Detect the presence of Ingreslock backdoor");
 script_category(ACT_ATTACK);
 script_family("Gain a shell remotely");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service1.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown", 1524);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/unknown");
if(!port) port = 1524;

if(!get_port_state(port)) exit(0);
if(!service_is_unknown(port:port) ) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

recv = recv(socket:soc, length:1024);
if(recv =~ "# $") {

  send(socket:soc, data:'id\r\n');
  recv = recv(socket:soc, length:1024);
  close(soc);

  if(recv =~ "uid=[0-9]+.*gid=[0-9]+") {
    security_hole(port:port);
  }  

}  

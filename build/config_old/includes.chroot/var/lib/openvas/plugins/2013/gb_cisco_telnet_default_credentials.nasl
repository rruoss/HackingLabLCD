###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telnet_default_credentials.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cisco Default Telnet Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_summary = "It was possible to login into the remote host using default credentials.";
tag_solution = "Change the password as soon as possible.";

desc = "
 Summary:
 " + tag_summary + "

 Solution:
 " + tag_solution;

if (description)
{

 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
 script_tag(name:"risk_factor", value:"Critical");
 script_id(103807);
 script_version("$Revision: 11 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-11 17:38:09 +0200 (Fri, 11 Oct 2013)");
 script_name("Cisco Default Telnet Login");
 script_description(desc);
 script_summary("Checks if login with default credentials is possible");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("telnetserver_detect_type_nd_version.nasl");
 script_require_ports("Services/telnet", 23);

 script_timeout(600);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }

 exit(0);
}


include("telnet_func.inc");
include("default_credentials.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(!get_port_state(port))exit(0);

default = try(vendor:'cisco');
if(!default)exit(0);

banner = get_telnet_banner(port:port);

if("User Access Verification" >!< banner && "cisco" >!< banner)exit(0);

foreach pw(default) {

  up = split(pw,sep:";", keep:FALSE);
  if(isnull(up[0]) || isnull(up[1]))continue;

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  user = up[0];
  pass = up[1];

  if(pass == "none")pass = "";

  send(socket:soc, data:user + '\r\n');
  ret = recv(socket:soc, length:1024);

  if("ass" >!< ret) {
    close(soc);
    sleep(1);
    continue;
  }  

  send(socket:soc, data:pass + '\r\n');
  ret = recv(socket:soc, length:1024);

  send(socket:soc, data:'show ver\r\n');

  ret = recv(socket:soc, length:4096);
  close(soc);

  if("Cisco IOS Software" >< ret || "Cisco Internetwork Operating System Software" >< ret) {

    report = desc + '\n\nIt was possible to login as user "' + user + '" with password "' + pass + '".\n'; ;
    security_hole(port:port, data:report);
    exit(0);

  }
}

exit(99);

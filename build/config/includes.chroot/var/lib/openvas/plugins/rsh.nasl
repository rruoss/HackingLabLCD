###############################################################################
# OpenVAS Vulnerability Test
# $Id: rsh.nasl 43 2013-11-04 19:51:40Z jan $
#
# Check for rsh Service 
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
tag_solution = "Disable rsh and use ssh instead.";
tag_summary = "rsh Service is running at this Host.
   rsh (remote shell) is a command line computer program which can execute
   shell commands as another user, and on another computer across a computer
   network.";

if(description)
{
 script_id(100080);
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-26 19:23:59 +0100 (Thu, 26 Mar 2009)");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "Check for rsh Service";
 script_name(name);
 
 desc = "
  
 Summary:
 " + tag_summary + "

 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Check for rsh Service";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 family = "Useless services";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/rsh", 514);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/rsh");
if(!port)port=514;
if(!get_port_state(port))exit(0);

soc = open_priv_sock_tcp(dport:port);
if(!soc)exit(0);

data = string('0\0',"root", '\0',"root",'\0','id\0'); #  Found in http://cpansearch.perl.org/src/ASLETT/Net-Rsh-0.05/Rsh.pm

send(socket:soc, data:data);
buf = recv(socket: soc, length: 8192);

if(strlen(buf)>0) {
 set_kb_item(name:"rsh/active", value:TRUE);
 register_service(port: port, proto: "rsh");

 if(egrep(pattern: "^uid=[0-9]+.*gid=[0-9]+.*", string: buf)) {
  set_kb_item(name: "rsh/login_from", value: string("root"));
  set_kb_item(name: "rsh/login_to", value: string("root"));
 }
 
 security_warning(port: port);
}

exit(0);

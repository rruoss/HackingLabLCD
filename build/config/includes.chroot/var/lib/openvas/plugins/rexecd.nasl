###############################################################################
# OpenVAS Vulnerability Test
# $Id: rexecd.nasl 15 2013-10-27 12:49:54Z jan $
#
# Check for rexecd Service 
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
tag_summary = "Rexecd Service is running at this Host.
   Rexecd (Remote Process Execution) has the same kind of functionality
   that rsh has : you can execute shell commands on a remote computer.

   The main difference is that rexecd authenticate by reading the
   username and password *unencrypted* from the socket.";

tag_solution = "Disable rexec Service.";

if(description)
{
 script_id(100111);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-08 12:09:59 +0200 (Wed, 08 Apr 2009)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Check for rexecd Service";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Check for rexec Service";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 family = "Useless services";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/rexecd", 512);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/rexecd");

if(!port)port = 512;

# sending a too long username. Without that too long username i did
# not get any response from rexecd. 

for (i=0; i<260; i=i+1) {
 username += string("x");
}  

rexecd_string = string(raw_string(0), username, raw_string(0), "xxx", raw_string(0), "id", raw_string(0));

if(get_port_state(port)) {

  soc = open_sock_tcp(port);
  if(soc) {
  
    send(socket:soc, data:rexecd_string);
    buf = recv_line(socket:soc, length:4096);
    close(soc);
    if( buf == NULL ) exit(0);
    
    if(ord(buf[0]) == 1 || egrep(pattern:"too long", string: buf)) {
      register_service(port:port, proto:"rexecd");
      security_warning(port:port, protocol:"tcp"); 
    } 
  }
}

exit(0);

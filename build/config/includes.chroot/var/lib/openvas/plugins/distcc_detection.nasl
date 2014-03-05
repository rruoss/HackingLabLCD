# OpenVAS Vulnerability Test
# $Id: distcc_detection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DistCC Detection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "distcc is a program to distribute builds of C, C++, Objective C or 
Objective C++ code across several machines on a network.  
distcc should always generate the same results as a local build, is simple 
to install and use, and is often two or more times faster than a local compile.

distcc by default trusts its clients completely that in turn could
allow a malicious client to execute arbitrary commands on the server.

For more information about DistCC's security see:
http://distcc.samba.org/security.html";

if(description)
{
 script_id(12638);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 
 name = "DistCC Detection";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Detect the presence of DistCC";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

 script_family("Service detection");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/unknown");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/unknown");
if ( known_service(port:port) ) exit(0);
if ( ! port ) port = 3632;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 { 
  req = string("DIST00000001", 
               "ARGC00000008",
               "ARGV00000002","cc",
               "ARGV00000002","-g",
               "ARGV00000003","-O2",
               "ARGV00000005","-Wall",
               "ARGV00000002","-c",
               "ARGV00000006","main.c",
               "ARGV00000002","-o",
               "ARGV00000006","main.o");

  send(socket:soc, data:req);

  req = string("DOTI0000001B", "int main()\n{\n return(0);\n}\n");

  send(socket:soc, data:req);

  response = recv(socket:soc, length:255);
#  display("response: ", response, "\n");

  if ("DONE00000" >< response)
  {
   register_service(port:port, proto:"distccd");
   security_hole(port);
  }
 }
}


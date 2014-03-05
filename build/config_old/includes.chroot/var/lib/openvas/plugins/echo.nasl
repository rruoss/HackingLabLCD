###############################################################################
# OpenVAS Vulnerability Test
# $Id: echo.nasl 43 2013-11-04 19:51:40Z jan $
#
# Check for echo Service 
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
tag_summary = "Echo Service is running at this Host.

   The echo service is an Internet protocol defined in RFC 862. It was
   originally proposed for testing and measurement of round-trip times in IP
   networks. While still available on most UNIX-like operating systems, testing
   and measurement is now performed with the Internet Control Message Protocol
   (ICMP), using the applications ping and traceroute.";

tag_solution = "Disable echo Service.";

if(description)
{
 script_id(100075);
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-24 15:43:44 +0100 (Tue, 24 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 script_cve_id("CVE-1999-0635");

 name = "Check for echo Service";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Check for echo Service";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 family = "Useless services";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/echo", 7);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");


port = get_kb_item("Services/echo");

if(!port)port = 7;

echo_string = string("OpenVAS-Echo-Test");

if(get_port_state(port)) {

  soc = open_sock_tcp(port);
  if(soc) {
  
    send(socket:soc, data:echo_string);
    buf = recv(socket:soc, length:4096);
    close(soc);
    if( buf == NULL ) exit(0);
  
    if(buf == echo_string) {
      register_service(port:port, proto:"echo");
      log_message(port:port, protocol:"tcp"); 
    } 
  }
}

if(get_udp_port_state(port)) {

  soc = open_sock_udp(port);
  if(soc) {

   send(socket:soc, data:echo_string);
   buf = recv(socket:soc, length:4096);
   close(soc);
   if(buf == echo_string) { 
     log_message(port:port, protocol:"udp");
   }
  }
}

exit(0);

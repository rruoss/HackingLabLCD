###############################################################################
# OpenVAS Vulnerability Test
# $Id: dns_server.nasl 43 2013-11-04 19:51:40Z jan $
#
# DNS Server Detection
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
tag_summary = "A DNS Server is running at this Host.
A Name Server translates domain names into IP addresses. This makes it
possible for a user to access a website by typing in the domain name instead of
the website's actual IP address.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100069";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-03-22 17:08:49 +0100 (Sun, 22 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 script_name("DNS Server Detection");
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_summary("Detect DNS Servers");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(53);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

# query '1.0.0.127.in-addr.arpa/PTR/IN'

data = raw_string(0xB8,0x4C,0x01,0x00,0x00,0x01,
                  0x00,0x00,0x00,0x00,0x00,0x00,
                  0x01,0x31,0x01,0x30,0x01,0x30,
                  0x03,0x31,0x32,0x37,0x07,0x69,
	          0x6E,0x2D,0x61,0x64,0x64,0x72,
	          0x04,0x61,0x72,0x70,0x61,0x00,
	          0x00, 0x0C, 0x00, 0x01);


if(get_udp_port_state(53))
 {
   soc = open_sock_udp(53);
   if (!soc) exit(0);

   send(socket:soc, data:data);
   buf = recv(socket:soc, length:4096);
   close(soc);
 
   if(strlen(buf) > 3) {
     if ( ord(buf[2]) & 0x80 ) {
      set_kb_item(name:"DNS/udp/53", value:TRUE);
      register_service(port: 53,  ipproto: "udp", proto: "dns");
      log_message(port:53, protocol:"udp");
     }
   }
 }
  
if(get_port_state(53))
 {
   soc = open_sock_tcp(53);
   if (!soc) exit(0);

   data = raw_string(0x00,0x28) + data;

   send(socket:soc, data:data);
   buf = recv(socket:soc, length:4096);
   close(soc);
   if( buf == NULL ) exit(0);

   if(strlen(buf) > 5) {
     if ( ord(buf[4]) & 0x80 ) {
       set_kb_item(name:"DNS/tcp/53", value:TRUE);
       register_service(port: 53,  ipproto: "tcp", proto: "dns");
       log_message(port:53, protocol:"tcp");
     }
   }
 } 

exit(0);

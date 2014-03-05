# OpenVAS Vulnerability Test
# $Id: sybase_asa_ping.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Sybase ASA Ping
#
# Authors:
# David Lodge 13/08/2007
# This script is based on sybase_blank_password.nasl which is (C) Tenable Security
#
# Copyright:
# Copyright (C) 2007 David Lodge
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
tag_summary = "The remote database server is affected by an information disclosure
vulnerability. 

Description :

The remote Sybase SQL Anywhere / Adaptive Server Anywhere database is
configured to listen for client connection broadcasts, which allows an
attacker to see the name and port that the Sybase SQL Anywhere /
Adaptive Server Anywhere server is running on.";

tag_solution = "Switch off broadcast listening via the '-sb' switch when starting
Sybase.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(80089);;
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Sybase ASA Ping";
 script_name(name);

 script_description(desc);
 
 summary = "Locate service enabled on Sybase server";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2007 David Lodge");
 family = "Databases";
 script_family(family);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.sybase.com/products/databasemanagement/sqlanywhere");
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

port = 2638;
if (!get_udp_port_state(port)) exit(0);

req = raw_string(
   0x1b, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x00, 0x12,
   "CONNECTIONLESS_TDS",
   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
   0x04, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x03, 0x01, 0x01,
   0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

soc = open_sock_udp(port);
if(soc)
{
   send(socket:soc, data:req);
   r  = recv(socket:soc, length:4096);
   close(soc);
   if(!r)exit(0);
 
   name="";
   length=ord(r[0x27]);
   for (i=0x28;i<0x27+length;i++)
   {
      name+=r[i];
   }

   offset=0x27+length+3;
   serverport=ord(r[offset])*256+ord(r[offset+1]);

   report = desc +
      string("\n\nPlugin output :\n\n") +
      "Database name: " + name + string("\n") +
      "Database port: " + serverport;

   security_warning(port:port, protocol:"udp", data:report);
}

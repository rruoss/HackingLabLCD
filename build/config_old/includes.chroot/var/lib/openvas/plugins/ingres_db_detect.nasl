###############################################################################
# OpenVAS Vulnerability Test
# $Id: ingres_db_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ingres Database Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "This host is running Ingres Database. Ingres Database is an open source
database management system.";

if (description)
{
 script_id(100479);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Ingres Database Detection");

desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 script_summary("Checks for the presence of Ingres Database");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown", 21071);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.ingres.com/products/ingres-database.php");
 exit(0);
}

include("byte_func.inc");
include("misc_func.inc");

port = "21071";
if(!get_tcp_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

req =
raw_string(0x23,0x00,0x4a,0x43,0x54,0x4c,0x43,0x52,0x01,0x01,0x02,0x02,0x01,0x0f,0x06,0x04,
           0x44,0x4d,0x4d,0x4c,0x03,0x0d,0x01,0x01,0x06,0x03,0x08,0xb8,0x97,0xc4,0xdf,0x07,
           0x89,0xe3,0xf1);

send(socket:soc, data:req);
buf = recv(socket:soc, length:256);

if(strlen(buf) && getword(blob:buf, pos:0) == strlen(buf) && "DMML" >< buf) {
  register_service(port:port, ipproto:"tcp", proto:"iigcd");
  security_note(port:port);
  exit(0);
}

exit(0);

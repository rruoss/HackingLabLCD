###############################################################################
# OpenVAS Vulnerability Test
# $Id: ms_rdp_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Detection of Microsoft Remote Desktop Protocol 
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
tag_summary = "The Microsoft Remote Desktop Protocol (RDP) is running at this host. Remote
 Desktop Services, formerly known as Terminal Services, is one of the components
 of Microsoft Windows (both server and client versions) that allows a user to
 access applications and data on a remote computer over a network.";

if (description)
{
 script_id(100062);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-19 19:54:28 +0100 (Thu, 19 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 desc = "
 Summary:
 " + tag_summary;

 script_name("Microsoft Remote Desktop Protocol Detection");  

 script_description(desc);
 script_summary("Check for Microsoft Remote Desktop Protocol");
 script_category(ACT_GATHER_INFO);
 script_family("Windows");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports(3389);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");

port = 3389;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req = raw_string(0x03,0x00,0x00,0x0b,0x06,0xe0,0x00,0x00,0x00,0x00,0x00); # found in amaps (http://freeworld.thc.org/thc-amap) appdefs.trig
send(socket:soc, data:req);
buf = recv(socket:soc, length:5);
if( buf == NULL ) exit(0);
close(soc);

response = hexstr(buf);

  if(response =~ "^0300000b06$" ) {
    security_note(port:port);
    exit(0);
   }

exit(0);

# OpenVAS Vulnerability Test
# $Id: line_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Too long line
#
# Authors:
# Michel Arboi <arboi@alussinan.org> 
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "It was possible to kill the service by sending a single long 
text line.
A cracker may be able to use this flaw to crash your software
or even execute arbitrary code on your system.";

if(description)
{
 script_id(11175);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 name = "Too long line";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Crashes a service by sending a too long line";
 script_summary(summary);
 script_category(ACT_FLOOD);
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";

 script_family(family);

 script_dependencies("find_service.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include('misc_func.inc');
ports = get_kb_list("Services/unknown");
if(isnull(ports))exit(0);

line = string(crap(512), "\r\n");

foreach port (make_list(ports))
{
    if ( service_is_unknown(port:port) ) 
    {
    port = int(port);
    s = open_sock_tcp(port);
    if (s)
    {
      send(socket: s, data: line);
      r = recv(socket:s, length:1); # Make sure data arrived
      close(s);
      s = open_sock_tcp(port);
      if (s) { close(s); }
      else { security_hole(port); }
    }
   }
}

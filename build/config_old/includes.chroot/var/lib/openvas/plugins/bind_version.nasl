# OpenVAS Vulnerability Test
# $Id: bind_version.nasl 41 2013-11-04 19:00:12Z jan $
# Description: Determine which version of BIND name daemon is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
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
tag_summary = "BIND 'NAMED' is an open-source DNS server from ISC.org.  Many proprietary
DNS servers are based on BIND source code.

The BIND based NAMED servers (or DNS servers) allow  remote users
to query for version and type information.  The query of the CHAOS
TXT record 'version.bind', will typically prompt the server to send
the information back to the querying source.";

tag_solution = "Using the 'version' directive in the 'options' section will block
the 'version.bind' query, but it will not log such attempts.";

if(description)
{
 script_id(10028);
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Determine which version of BIND name daemon is running";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Determine which version of BIND name daemon is running";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "General";
 script_family(family);
 script_dependencies("dnsmasq_version.nasl");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
#
# We try to gather the version number via TCP first, and if this
# fails (or if the port is closed), we'll try via UDP
#
#

include("misc_func.inc");

##
# Don't detect dnsmasq as BIND.
if(get_kb_item("dnsmasq/version"))exit(0);

# start report off with generic description ... lots of proprietary DNS servers (Cisco, QIP, a bunch more
# are all BIND-based...

data = string("BIND 'NAMED' is an open-source DNS server from ISC.org.\n");
data += string("Many proprietary DNS servers are based on BIND source code.\n\n");

data += string("The BIND based NAMED servers (or DNS servers) allow remote users\n");
data += string("to query for version and type information.  The query of the CHAOS\n");
data += string("TXT record 'version.bind', will typically prompt the server to send\n");
data += string("the information back to the querying source.\n");


 soctcp53 = 0;
 
 if(get_port_state(53))
  {
  soctcp53 = open_sock_tcp(53);
 }
 if(!soctcp53){
  if(!(get_udp_port_state(53)))exit(0);
  socudp53 = open_sock_udp(53);
  soc = socudp53;
  offset = 0;
  }
  else {
  	soc = soctcp53;
	offset = 2;
  	}
  
 if (soc)
 {
  
  raw_data = raw_string(
			0x00, 0x0A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x07);
  
  if(offset)raw_data = raw_string(0x00, 0x1E) + raw_data;
  
  raw_data = raw_data + "VERSION";
  raw_data = raw_data + raw_string( 0x04 );
  raw_data = raw_data + "BIND";
  raw_data = raw_data + raw_string(
				   0x00, 0x00, 0x10, 0x00, 0x03);

  send(socket:soc, data:raw_data);
  result = recv(socket:soc, length:1000);
  if (result)
  {
    if ((result[0+offset] == raw_string(0x00)) && (result[1+offset] == raw_string(0x0A)))
    {
# ignore recursion request and recursion available bits in answer
# (usually the request bit is set if it was set in the query but
# this is not necessary, the recursion available bit is clear if
# the server doesn't allow recursion which should be the case
# for a properly setup external primary nameserver
     if (((result[2+offset] == raw_string(0x85))||(result[2+offset] == raw_string(0x84))) && ((result[3+offset] == raw_string(0x80))||(result[3+offset] == raw_string(0x00))))
     {
      if ((result[4+offset] == raw_string(0x00)) && (result[5+offset] == raw_string(0x01)))
	  {
       if ((result[6+offset] == raw_string(0x00)) && (result[7+offset] == raw_string(0x01)))
	   {
# take care of result compression (we know that a pointer starts with c0
# or higher)
		if(result[30+offset]>=0xc0)base=40;
		else base=52;
		size = ord(result[base+1+offset]);
		slen = base + 3 + offset - 1;
		if(slen > strlen(result))exit(0);
		if (size > 0)
		{
		 hole_data = "";
		 for (i = 0; i < size - 1; i = i + 1)
		 {
		  hole_data = hole_data + result[base+3+i+offset];
		 }
   
                 if("dnsmasq" >< hole_data || "powerdns" >< hole_data)exit(0);
		 if(hole_data !~ "^[0-9]")exit(0); 

		 data += string("\nThe remote bind version is : ", hole_data,"\n\n");
                 data += string("Solution :\n");
                 data += string("Using the 'version' directive in the 'options' section will block\n");
                 data += string("the 'version.bind' query, but it will not log such attempts.\n");

		 if(offset)proto = "tcp";
		 else proto = "udp";
		 security_note(port:53, data:data, protocol:proto);
		 set_kb_item(name:"bind/version",value:hole_data);
		}
	   }
	  }
     }
    }
 close(soc);
  }
 }


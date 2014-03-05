###############################################################################
# OpenVAS Vulnerability Test
# $Id: unbound_version.nasl 44 2013-11-04 19:58:48Z jan $
#
# Detection of Unbound DNS resolver Version
#
# Authors:
# Michael Meyer
#
# Based on bind_version.nasl from Noam Rathaus <noamr@securiteam.com> 
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
tag_summary = "The Unbound DNS resolver is running at this host.
Unbound is a validating, recursive, and caching DNS resolver. 

The Unbound DNS resolver allow remote users to query for version and type
information. The query of the CHAOS TXT record 'version.bind', will
typically prompt the server to send the information back to the
querying source.";

tag_solution = "Set 'hide-version: yes' in unbound.conf.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if (description)
{
 script_id(100417);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Unbound DNS resolver Detection");  

 script_description(desc);
 script_summary("Check for the version of Unbound DNS resolver");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","dns_server.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://unbound.net");
 exit(0);
}

include("misc_func.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100417";
SCRIPT_DESC = "Unbound DNS resolver Detection";

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
  raw_data = raw_data + raw_string(0x00, 0x00, 0x10, 0x00, 0x03);

  send(socket:soc, data:raw_data);
  result = recv(socket:soc, length:1000);
  if (result)
  {
    if ((result[0+offset] == raw_string(0x00)) && (result[1+offset] == raw_string(0x0A)))
    {
     if (((result[2+offset] == raw_string(0x81))||(result[2+offset] == raw_string(0x84))) && ((result[3+offset] == raw_string(0x80))||(result[3+offset] == raw_string(0x00))))
     {
      if ((result[4+offset] == raw_string(0x00)) && (result[5+offset] == raw_string(0x01)))
	  {
       if ((result[6+offset] == raw_string(0x00)) && (result[7+offset] == raw_string(0x01)))
	   {
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
		 if(offset)proto = "tcp";
		 else proto = "udp";

                 if("unbound" >!< hole_data)exit(0);

		 hole_data -= string("unbound ");

		 info = string("\n\nUnbound Version '"); 
		 info += hole_data;
		 info += string("' was detected on the remote Host\n\n");  
		
		desc = desc + info;    

		set_kb_item(name:"unbound/version",value:hole_data);
  register_host_detail(name:"App", value:string("cpe:/a:unbound:unbound:",hole_data), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
		security_note(port:53, data:desc, protocol:proto);
		close(soc);
		exit(0);
		}
	   }
	  }
     }
    }
 close(soc);
 exit(0);
  }
 }

exit(0);

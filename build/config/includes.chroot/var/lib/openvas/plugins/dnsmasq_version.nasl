###############################################################################
# OpenVAS Vulnerability Test
# $Id: dnsmasq_version.nasl 43 2013-11-04 19:51:40Z jan $
#
# Detection of Dnsmasq Version
#
# Authors:
# Michael Meyer
#
# Based on bind_version.nasl from Noam Rathaus <noamr@securiteam.com> 
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
tag_summary = "Detection of Dnsmasq

The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100266";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-09-01 22:29:29 +0200 (Tue, 01 Sep 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Dnsmasq Detection");  
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Check for the version of Dnsmasq");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_dependencies("find_service.nasl");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("global_settings.inc");
include("misc_func.inc");

## Constant values
SCRIPT_DESC = "Dnsmasq Detection";

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
     if (((result[2+offset] == raw_string(0x85))||(result[2+offset] == raw_string(0x84))) && ((result[3+offset] == raw_string(0x80))||(result[3+offset] == raw_string(0x00))))
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

		 if("dnsmasq" >!< hole_data)exit(0);

                 concluded = hole_data;

		 hole_data -= string("dnsmasq-");

                 close(soc);

		 set_kb_item(name:"dnsmasq/version",value:hole_data);

                 cpe = build_cpe(value: hole_data, exp:"^([0-9.]+)",base:"cpe:/a:thekelleys:dnsmasq:");
                 if(!cpe)
                   cpe = 'cpe:/a:thekelleys:dnsmasq';

                 register_product(cpe:cpe, location:"53/" + proto, nvt:SCRIPT_OID, port:"53");

                 log_message(data: build_detection_report(app:"Dnsmasq", version:hole_data, install:"53/" + proto, cpe:cpe, concluded: concluded),
                             port:port);

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

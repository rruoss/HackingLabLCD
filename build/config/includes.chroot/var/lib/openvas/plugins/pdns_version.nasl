###############################################################################
# OpenVAS Vulnerability Test
# $Id: pdns_version.nasl 44 2013-11-04 19:58:48Z jan $
#
# Detection of PowerDNS
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
tag_summary = "The PowerDNS Nameserver is running at this host.

The PowerDNS Nameserver allow remote users to query for version and
type information. The query of the CHAOS TXT record 'version.bind',
or 'version.pdns' will typically prompt the server to send the
information back to the querying source.";

tag_solution = "Set 'version-string' in pdns.conf or recursor.conf.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


if (description)
{
 script_id(100432);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2010-01-07 12:29:25 +0100 (Thu, 07 Jan 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("PowerDNS Detection");  

 script_description(desc);
 script_summary("Check for the version of PowerDNS");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","dns_server.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.powerdns.com/");
 exit(0);
}

include("misc_func.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100432";
SCRIPT_DESC = "PowerDNS Detection";

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
  raw_data = raw_data + "PDNS";
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

                 if("powerdns" >!< tolower(hole_data))exit(0);

		 version = eregmatch(pattern: "(PowerDNS [a-zA-Z ]*[0-9.]+)", string: hole_data, icase: TRUE);
		 if(isnull(version[1]))exit(0);

		 info = string("\n\nPowerDNS Version '"); 
		 info += version[1];
		 info += string("' was detected on the remote Host\n\n");  
		
 		 desc = desc + info;    

		set_kb_item(name:"powerdns/version",value:version[1]);
		num_version = eregmatch(pattern:"([0-9.]+)", string: version[1]);

		if("Recursor" >< version[1]) {
     register_host_detail(name:"App", value:string("cpe:/a:powerdns:recursor:",num_version[1]), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
		} else {
                  register_host_detail(name:"App", value:string("cpe:/a:powerdns:powerdns:",num_version[1]), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
		}

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

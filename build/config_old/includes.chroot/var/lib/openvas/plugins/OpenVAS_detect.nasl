###############################################################################
# OpenVAS Vulnerability Test
# $Id: OpenVAS_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# OpenVAS Scanner Detection
#
# Authors:
# Michael Meyer
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
tag_summary = "Detection of OpenVAS Scanner.
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100076";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-24 18:59:36 +0100 (Tue, 24 Mar 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"detection", value:"remote probe");
 script_name("OpenVAS Scanner Detection");
 
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Checks for the presence of OpenVAS Scanner");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_family("Product detection");
 script_require_ports(9390,9391);
 script_dependencies("find_service2.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");
  
function probe(port)
{
  soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
  if (soc) {
    for(count=0; count < 3 ; count++)
    {
     senddata = string("< OTP/1.", count, " >\n");
     send(socket:soc, data:senddata);
     recvdata = recv_line(socket:soc, length:20);
     if (ereg(pattern:"^< OTP/1." + count + " >$",string:recvdata)) {
	close(soc);

        cpe = 'cpe:/a:openvas:openvas_scanner';
        vers = 'unknown';
        install = port + '/tcp';

        register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);
        log_message(data: build_detection_report(app:"OpenVAS Scanner", version:vers, install:install, cpe:cpe, concluded: recvdata),
                    port:port);


	break;
     }  	
    }
  }
}

port = get_kb_item("Services/unknown");

if(port)
{
 if (known_service(port: port)) exit(0); 
 if(get_port_state(port))
  probe(port:port);
}
else
{
 if(get_port_state(9390))
  probe(port:9390);
 if(get_port_state(9391))
  probe(port:9391);  
}

exit(0);

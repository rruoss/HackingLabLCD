# OpenVAS Vulnerability Test
# $Id: webshield_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: WebShield Appliance detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "Detection of WebShield Appliance.
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.17368";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("WebShield Appliance detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for WebShield Appliance console management");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Product detection");
 script_dependencies("http_version.nasl");
 script_require_ports(443);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

function https_get(port, request)
{
    if(get_port_state(port))
    {

         soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
         if(soc)
         {
            send(socket:soc, data:string(request,"\r\n"));
            result = http_recv(socket:soc);
            close(soc);
            return(result);
         }
    }
}

port = 443;
if(get_port_state(port))
{
 req1=http_get(item:"/strings.js", port:port);
 if ( "Server: WebShield Appliance" >< req1 )
 {
  req = https_get(request:req1, port:port);
  #var WEBSHIELD_TITLE="WebShield Appliance v3.0";

  title = egrep(pattern:"WEBSHIELD_TITLE=", string:req);
  if ( ! title ) exit(0);

  vers = 'unknown';
  version = eregmatch(pattern:'WEBSHIELD_TITLE="WebShield Appliance v(0-9.)+"', string:title, icase:TRUE);

  if(!isnull(version[1])) {
    vers = version[1];
  }
 
  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:network_associates:webshield:");
  if(!cpe)
    cpe = 'cpe:/a:network_associates:webshield';

  register_product(cpe:cpe, location:"/strings.js", nvt:SCRIPT_OID, port:port);

  log_message(data: build_detection_report(app:"WebShield Appliance", version:vers, install:"/", cpe:cpe, concluded: version[0]),
              port:port);

  exit(0);

  
  }
}

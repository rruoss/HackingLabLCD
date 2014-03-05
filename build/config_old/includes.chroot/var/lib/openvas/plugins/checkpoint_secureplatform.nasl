# OpenVAS Vulnerability Test
# $Id: checkpoint_secureplatform.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Checkpoint Secure Platform detection
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
tag_summary = "Detection of Checkpoint Secure Platform.
                    
The script sends a connection request to the server and attempts to
detect Checkpoint Secure Platform from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.17584";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Checkpoint Secure Platform detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 
 script_summary("Checkpoint Secure Platform web console management");
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

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = 443;
if(get_port_state(port))
{
 req = http_get(item:"/deploymentmanager/index.jsp", port:port);
 rep = https_get(request:req, port:port);
 if( rep == NULL ) exit(0);
 #<title>SecurePlatform NG with Application Intelligence (R55) </title>
 if ("<title>SecurePlatform NG with Application Intelligence " >< rep)
 {

   cpe = 'cpe:/a:checkpoint:secure_platform_ng';
   set_kb_item(name:"checkpoint_secure_platform/installed",value:TRUE);

   register_product(cpe:cpe, location:"/deploymentmanager/index.jsp", nvt:SCRIPT_OID, port:port);

   log_message(data: build_detection_report(app:"Checkpoint Secure Platform", version:"unknown", install:"/deploymentmanager/", cpe:cpe, concluded: "<title>SecurePlatform NG with Application Intelligence"),
               port:port);

   exit(0);

 }
}

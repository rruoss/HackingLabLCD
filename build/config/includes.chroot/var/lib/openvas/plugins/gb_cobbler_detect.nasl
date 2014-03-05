###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cobbler_detect.nasl 12 2013-10-27 11:15:33Z jan $
#
# Cobbler Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
tag_summary = "Detection of Cobbler
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103514";   

if (description)
{
 
 script_tag(name:"risk_factor", value:"None");
 script_tag(name:"cvss_base", value:"0.0");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-07-12 16:08:56 +0200 (Thu, 12 Jul 2012)");
 script_name("Cobbler Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);

 script_summary("Checks for the presence of Cobbler");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

SCRIPT_DESC = "Cobbler Detection";

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

url = '/cobbler_api';
host = get_host_name();

xml = '<?xml version="1.0"?>
<methodCall>
  <methodName>extended_version</methodName>
</methodCall>';

len = strlen(xml);

req = string("POST ",url," HTTP/1.1\r\n",
             "Host: ", host ,"\r\n",
             "Content-Length:",len,"\r\n",
             "\r\n",
             xml);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<methodResponse>" >!< result || "<name>version</name>" >!< result) exit(0);

lines = split(result);

for(i=0; i < max_index( lines ); i++) {

  if("<name>version</name>" >< lines[i]) {
    
    version = eregmatch(pattern:"<string>([^<]+)</string>", string:lines[i+1]);
    
    if(isnull(version[1]))exit(0);

    vers = version[1];

    set_kb_item(name:"Cobbler/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:michael_dehaan:cobbler:");
    if(isnull(cpe))
      cpe = 'cpe:/a:michael_dehaan:cobbler';

    register_product(cpe:cpe, location:url, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Cobbler", version:vers, install:url, cpe:cpe, concluded: version[0]),
                port:port);

    exit(0);


  }
}  

exit(0);

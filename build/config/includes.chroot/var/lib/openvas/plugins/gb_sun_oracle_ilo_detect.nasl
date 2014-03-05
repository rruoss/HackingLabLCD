###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_oracle_ilo_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Sun/Oracle Integrated Lights Out Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103775";   

if (description)
{
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"detection", value:"remote probe");
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-27 15:18:12 +0200 (Tue, 27 Aug 2013)");
 script_name("Sun/Oracle Integrated Lights Out Manager Detection");

  tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

 script_description(desc);
 script_summary("Checks for the presence of Sun/Oracle Integrated Lights Out Manager");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80, 443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(banner !~ "Server: (Sun|Oracle)-ILOM-Web-Server/")exit(0);

host = get_host_name();

transport = get_port_transport(port);

soc = open_sock_tcp(port, transport:transport);
if(!soc)exit(0); 

req = 'GET /home.asp HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'Connection: close\r\n\r\n';

send(socket:soc, data:req);

while(r = recv(socket:soc, length:4096)) {
  res += r;
}

close(soc);

if("<title>Integrated Lights Out Manager" >!< res) {
  exit(0);
}

vers = 'unknown';

req = 'GET /about/frame-content.asp HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'Connection: close\r\n\r\n';

soc = open_sock_tcp(port, transport:transport);
if(soc) {

  send(socket:soc, data:req);

  while(z = recv(socket:soc, length:4096)) {
    buf += z;
  }

  close(soc);

  version = eregmatch(string:buf, pattern:'Version ([^<]+)</div>');
  if(!isnull(version[1]))vers = version[1];

}

set_kb_item(name:"sun_oracle_ilo/installed",value:TRUE);

if(vers == "unknown")
  cpe = "cpe:/a:sun:embedded_lights_out_manager";
else
  cpe = "cpe:/a:sun:embedded_lights_out_manager:" + vers;

register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);

log_message(data: build_detection_report(app:"Sun/Oracle Integrated Lights Out Manager",
                                         version:vers,
                                         install:"/",
                                         cpe:cpe,
                                         concluded: version[0]),
                                         port:port);

exit(0);

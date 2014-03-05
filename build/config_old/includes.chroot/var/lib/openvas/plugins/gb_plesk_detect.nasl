###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plesk_detect.nasl 18 2013-10-27 14:14:13Z jan $
#
# Plesk  Detection
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
tag_summary = "Detection of Plesk.
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103740";   

if (description)
{
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"detection", value:"remote probe");
 script_tag(name:"risk_factor", value:"None");
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 18 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:14:13 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-17 16:27:41 +0200 (Mon, 17 Jun 2013)");
 script_name("Plesk  Detection");
 desc = "
 Summary:
 " + tag_summary;
  script_description(desc);
 script_summary("Checks for the presence of Plesk");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = 8443;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port, transport:ENCAPS_SSLv23);
if(!soc)exit(0);

host = get_host_name();
url = "/login_up.php3";

req = 'GET ' + url + ' HTTP/1.1\r\n' +
      "Host: " + host + '\r\n\r\n';

send(socket:soc, data:req);

while(resp = recv(socket:soc, length: 1024)) {
  buf +=  resp;
}  

close(soc);

if("<title>Parallels Plesk Panel" >< buf) {

  vers = 'unknown';

  version = eregmatch(pattern:"<title>Parallels Plesk Panel ([0-9.]+)</title>", string:buf);

  if(!isnull(version[1]))
     vers = version[1];

  set_kb_item(name:"plesk/installed",value:TRUE);

  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:parallels:parallels_plesk_panel:");
  if(isnull(cpe))
    cpe = 'cpe:/a:parallels:parallels_plesk_panel';

  register_product(cpe:cpe, location:"/", nvt:SCRIPT_OID, port:port);  

  log_message(data: build_detection_report(app:"Plesk", version:vers, install:"/", cpe:cpe, concluded: version[0]),
              port:port);

  exit(0);


}  

exit(0);

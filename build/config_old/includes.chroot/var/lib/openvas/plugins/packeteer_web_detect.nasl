# OpenVAS Vulnerability Test
# $Id: packeteer_web_detect.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Packeteer/Bluecoat Web Management Interface Detection
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2006-2007 nnposter
#
# Updated by Michael Meyer <michael.meyer@greenbone.net> 03-26-2013
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
tag_summary = "Packeteer Web Management Interface Detection.
The script sends a connection request to the server and attempts to
determine if the host is a Packeteer/Bluecoat PacketShaper from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.80031";

if (description)
    {
    script_oid(SCRIPT_OID);
    script_version("$Revision: 16 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
    script_tag(name:"risk_factor", value:"None");
    script_tag(name:"detection", value:"remote probe");
    script_name("Packeteer/Bluecoat Web Management Interface Detection");
    desc = "
    Summary:
    " + tag_summary;
  script_description(desc);
    script_summary("Detection of Packeteer/Bluecoat web management interface");
    script_family("Product detection");
    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (c) 2006-2007 nnposter");
    script_dependencies("http_version.nasl");
    script_require_ports("Services/www",80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
    }

include("http_func.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!get_tcp_port_state(port)) exit(0);

resp = http_send_recv(port:port,data:http_get(item:"/login.htm",port:port));
if (!resp) exit(0);

server = egrep(pattern:"^Server: *httpd/1\.",string:resp,icase:TRUE);
cookie = egrep(pattern:"^Set-Cookie: *[^a-z0-9]PScfgstr=",string:resp,icase:TRUE);
if (!server || !cookie) exit(0);

if(!eregmatch(pattern:"PacketShaper Login</title>", string: resp, icase:TRUE))exit(0);
model = eregmatch(pattern:">PacketShaper ([0-9]+)<", string:resp);

if(!isnull(model[1]))md = model[1];

cpe = 'cpe:/h:bluecoat:packetshaper';

if(md) cpe += '_' + md;

set_kb_item(name:"bluecoat_packetshaper/installed", value:TRUE);
set_kb_item(name:string("bluecoat_packetshaper/port"), value:port);

register_product(cpe:cpe, location:"/login.htm", nvt:SCRIPT_OID, port:port);

log_message(data: build_detection_report(app:"Packeteer/Bluecoat PacketShaper " + md, version:'unknown', install:'/', cpe:cpe, concluded: 'remote probe'),
            port:port);

exit(0);

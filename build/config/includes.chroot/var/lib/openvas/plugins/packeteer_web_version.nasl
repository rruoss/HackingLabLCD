# OpenVAS Vulnerability Test
# $Id: packeteer_web_version.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Packeteer Web Management Interface Version
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2006-2007 nnposter
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
tag_summary = "It is possible to determine the version of the remote web application. 

Description :

OpenVAS was able to determine the software version of the Packeteer web
management interface running on the remote host.";

    desc="
    Summary:
    " + tag_summary;

if (description)
    {
    script_id(80033);
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"risk_factor", value:"None");
    name="Packeteer Web Management Interface Version";
    script_name(name);

    script_description(desc);

    summary="Tests for Packeteer web interface version";
    script_summary(summary);

    family="Web application abuses";
    script_family(family);

    script_category(ACT_GATHER_INFO);
    script_copyright("This script is Copyright (c) 2006-2007 nnposter");
    script_dependencies("packeteer_web_login.nasl");
    script_require_keys("www/packeteer");
    script_require_ports("Services/www",80);
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
    }

# Notes:
# - Info page is bigger than 8K and PacketShaper does not use Content-Length.
#   The script uses custom http_send_recv_length() to retrieve the entire page.


include("http_func.inc");
include("misc_func.inc");


if (!get_kb_item("www/packeteer")) exit(0);


function set_cookie (data,cookie)
{
local_var EOL,req;
EOL='\r\n';
req=ereg_replace(string:data,pattern:EOL+'Cookie:[^\r\n]+',replace:"");
req=ereg_replace(string:req,pattern:EOL+EOL,replace:EOL+cookie+EOL);
return req;
}


function http_send_recv_length (port,data,length)
{
local_var sock,resp;
sock=http_open_socket(port);
if (!sock) return;
send(socket:sock,data:data);
resp=http_recv_length(socket:sock,bodylength:length);
http_close_socket(sock);
return resp;
}


function get_version (port,cookie)
{
local_var req,resp,match;
if (!port || !cookie) return;
if (!get_tcp_port_state(port)) return;
req=set_cookie(data:http_get(item:"/info.htm",port:port),cookie:cookie);
resp=http_send_recv_length(port:port,data:req,length:64000);
if (!resp) return;
match=eregmatch(
        pattern:'makeState\\("Software(.nbsp.| )Version:", *"([0-9A-Za-z.]+)',
        string:resp);
return match[2];
}


port=get_http_port(default:80);
product=get_kb_item("www/"+port+"/packeteer");
if (!get_tcp_port_state(port) || !product) exit(0);
if (!get_kb_item('/tmp/http/auth/'+port)) exit(0);

version=get_version(port:port,cookie:get_kb_item("/tmp/http/auth/"+port));
if (!version) exit(0);

replace_kb_item(name:"www/"+port+"/packeteer/version",value:version);
report = string(
  desc,
  "\n\n",
  "Plugin output :\n",
  "\n",
  "Packeteer "+product+" web interface version is "+version
);
security_note(port:port,data:report);

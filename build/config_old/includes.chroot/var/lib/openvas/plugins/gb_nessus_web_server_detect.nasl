###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nessus_web_server_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Nessus Web Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script finds the running version of Nessus Web Server and
  saves the result in KB.";

if(description)
{
  script_id(801392);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Nessus Web Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the version of Nessus Web Server in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_require_ports("Services/www", 8834);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("openvas-https.inc");

port = get_http_port(default:8834);
if(!port){
  port =8834;
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_http_banner(port:port);
if("Server: NessusWWW" >< banner)
{
  ## Construct https Request
  sndReq = string("GET /feed", " HTTP/1.1\r\n",
                  "Host: ", get_host_name(),":", port, "\r\n",
                  "User-Agent: Mozilla/5.0\r\n");
  rcvRes = https_req_get(port:port, request:sndReq);

  ## Check for the version of web server
  if("web_server_version" >< rcvRes )
  {
    nwsVer = eregmatch(pattern:"web_server_version>([0-9.]+)", string:rcvRes);
    if(!isnull(nwsVer[1]))
    {
      ## Set the web server version in kb
      set_kb_item(name:"www/" + port + "/Nessus/Web/Server", value:nwsVer[1]);
      security_note(data:"Nessus Web Server " + nwsVer[1] + " was detected" +
                     " on the host", port:port);
    }
  }
}

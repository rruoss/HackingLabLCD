###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ziproxy_server_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Ziproxy Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the installed version of Ziproxy Server
  and sets the version in KB.";

if(description)
{
  script_id(900522);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Ziproxy Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of Ziproxy Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900522";
SCRIPT_DESC = "Ziproxy Server Version Detection";

zipPort = get_http_port(default:8080);
if(!zipPort){
  zipPort = 8080;
}

if(get_port_state(zipPort))
{
  sndReq = string("GET / \r\n\r\n", "Host: ", get_host_name(), "\r\n");
  rcvRes = http_keepalive_send_recv(port:zipPort, data:sndReq);
  if("Server: ziproxy" >< rcvRes)
  {
    # Grep the Ziproxy Server Version from response
    ziproxyVer = eregmatch(pattern:"ziproxy/([0-9.]+)", string:rcvRes);

    if(ziproxyVer[1] != NULL){
      set_kb_item(name:"www/" + zipPort + "/Ziproxy", value:ziproxyVer[1]);
      security_note(data:"Ziproxy Server version " + ziproxyVer[1] +
                         " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:ziproxyVer[1], exp:"^([0-9.]+)", base:"cpe:/a:ziproxy:ziproxy:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

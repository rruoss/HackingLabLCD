###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Adobe Flash Media Server Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script detects the version of Adobe Flash Media Server and
  sets the result in the KB.";

if(description)
{
  script_id(800559);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Adobe Flash Media Server Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for the Version of Adobe Flash Media Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 1111);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800559";
SCRIPT_DESC = "Adobe Flash Media Server Detection";

fmsPort = get_http_port(default:1111);
if(!fmsPort){
  fmsPort = 1111;
}

if(!get_port_state(fmsPort)){
  exit(0);
}

sndReq = string("GET / HTTP/1.1 \r\n\r\n");
rcvRes = http_send_recv(port:fmsPort, data:sndReq);
if("FlashCom" >< rcvRes)
{
  fmsVer = eregmatch(pattern:"FlashCom/([0-9.]+)", string:rcvRes);
  if(fmsVer[1] != NULL)
  {
    set_kb_item(name:"www/" + fmsPort + "/Adobe/FMS", value:fmsVer[1]);
    security_note(data:"FlashCom version " + fmsVer[1] + " was detected on the host");
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:fmsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:adobe:flash_media_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}

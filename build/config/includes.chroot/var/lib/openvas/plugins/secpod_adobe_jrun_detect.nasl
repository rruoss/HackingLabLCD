###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_jrun_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Adobe JRun Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of Adobe JRun and
  sets the version in KB.";

if(description)
{
  script_id(900822);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Sun Adobe JRun Version Detection");

  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of Adobe JRun");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8000);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900822";
SCRIPT_DESC = "Sun Adobe JRun Version Detection";

jrunPort = get_http_port(default:8000);
if(!jrunPort){
  jrunPort = 8000;
}

if(!get_port_state(jrunPort)){
  exit(0);
}

sndReq = http_get(item:string("/"), port:jrunPort);
rcvRes = http_send_recv(port:jrunPort, data:sndReq);

if(egrep(pattern:"Server: JRun Web Server", string:rcvRes) &&
   egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
{
  # Grep the Adobe/Macromedia JRun Version from Response
  jrunVer = eregmatch(pattern:">Version ([0-9.]+)", string:rcvRes);

  if(jrunVer[1] != NULL){
    set_kb_item(name:"/Adobe/JRun/Ver", value:jrunVer[1]);
    security_note(data:"Adobe JRun version " + jrunVer[1] +
                                      " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value: jrunVer[1], exp:"^([0-9.]+)",base:"cpe:/a:adobe:jrun:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}

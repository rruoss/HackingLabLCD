##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codemeter_webadmin_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# CodeMeter WebAdmin Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the running version CodeMeter WebAdmin
  and sets the result in KB";

if(description)
{
  script_id(801988);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("CodeMeter WebAdmin Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of CodeMeter WebAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("cpe.inc");
include("http_func.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801988";
SCRIPT_DESC = "CodeMeter WebAdmin Version Detection";

## default port
cwaPort = 22350;

##Check the port status
if(!get_port_state(cwaPort)){
  exit(0);
}

sndReq = http_get(item:string("/home.html"), port:cwaPort);
rcvRes = http_send_recv(port:cwaPort, data:sndReq, bodyonly:TRUE);

## Cinfirm the application
if("<title>CodeMeter | WebAdmin</title>" >!< rcvRes){
  exit(0);
}

## Match the version
cwaVer = eregmatch(pattern:"WebAdmin Version.*[^\n]Version ([0-9.]+)",
                  string:rcvRes);

if(cwaVer[1] != NULL)
{
  ## Set the version in KB
  set_kb_item(name:"www/"+ cwaPort + "/CodeMeter_WebAdmin", value:cwaVer[1]);
  security_note(data:"CodeMeter WebAdmin version " + cwaVer[1] +
                     " was detected on the host");

  ## build cpe and store it as host_detail
  cpe = build_cpe(value:cwaVer[1], exp:"^([0-9.]+)",
        base:"cpe:/a:wibu:codemeter_webadmin:");

  ## Register the host details
  if(!isnull(cpe)){
    register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
  }
}

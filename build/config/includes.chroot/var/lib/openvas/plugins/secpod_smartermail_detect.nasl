###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartermail_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# SmarterMail Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "This script detects the running version of SmarterMail
  and sets the result in KB.";

if(description)
{
  script_id(902258);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-10-01 08:36:34 +0200 (Fri, 01 Oct 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("SmarterMail Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of SmarterMail");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl", "find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902258";
SCRIPT_DESC = "SmarterMail Version Detection";

smPort = "9998";
if(!get_port_state(smPort)){
  exit(0);
}

smBanner = get_http_banner(port:smPort);
if("Server: SmarterTools" >!< smBanner){
  exit(0);
}

sndReq = http_get(item:"/Login.aspx", port:smPort);
rcvRes = http_send_recv(port:smPort, data:sndReq);

if("SmarterMail Login - SmarterMail" >< rcvRes)
{
  version = eregmatch(pattern:">SmarterMail Free ([0-9.]+)", string:rcvRes);
  if(version[1])
  {
    set_kb_item(name:"SmartMail/Ver", value:version[1]);
    security_note(data:"SmartMail version " + version[1] + " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:smartertools:smartermail:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}

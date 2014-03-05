###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Microsoft IIS Webserver Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "This script detects the installed MS IIS Webserver and sets the
  result in KB.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900710";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Microsoft IIS Webserver Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of Microsoft IIS in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_DESC = "Microsoft IIS Webserver Version Detection";

iisPort = get_http_port(default:80);
if(!iisPort){
  iisPort = 80;
}

if(!get_port_state(iisPort)){
  exit(0);
}

request = http_get(item:string("/"), port:iisPort);
response = http_send_recv(port:iisPort, data:request);

if("Microsoft-IIS" >!< response){
  exit(0);
}

iisVer = eregmatch(pattern:"IIS\/([0-9.]+)", string:response);
if(iisVer[1] != NULL){
  # KB for Internet Information Service (IIS)
  set_kb_item(name:"IIS/" + iisPort + "/Ver", value:iisVer[1]);
  set_kb_item(name:"IIS/installed",value:TRUE);
   
  ## build cpe and store it as host_detail
  cpe = build_cpe(value: iisVer[1], exp:"^([0-9.]+)", base:"cpe:/a:microsoft:iis:");
  if(isnull(cpe))
    cpe = 'cpe:/a:microsoft:iis';

  register_product(cpe:cpe, location:iisPort + '/tcp', nvt:SCRIPT_OID, port:iisPort);
  log_message(data: build_detection_report(app:"Microsoft IIS Webserver", version:iisVer[1], install:iisPort + '/tcp', cpe:cpe, concluded: iisVer[0]),
              port:iisPort);

}

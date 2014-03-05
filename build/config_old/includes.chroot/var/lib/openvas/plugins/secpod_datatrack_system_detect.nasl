###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_datatrack_system_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# DataTrack System Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_summary = "This script finds the installed DataTrack System version and saves
  the result in KB.";

if(description)
{
  script_id(902061);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("DataTrack System Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of DataTrack System in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_require_ports("Services/www", 81);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902061";
SCRIPT_DESC = "DataTrack System Version Detection";

dtsPort = get_http_port(default:81);
if(!dtsPort){
  exit(0);
}

banner = get_http_banner(port:dtsPort);

## Confirm the application
if("Server: MagnoWare" >< banner || ">DataTrack Web Client<" >< banner)
{
  ## Grep for the version
  dtsVer = eregmatch(pattern:"MagnoWare/([0-9.]+)", string:banner);
  if(dtsVer[1] != NULL)
  {
    ## Set the KB value
    set_kb_item(name:"www/" + dtsPort + "/DataTrack_System", value:dtsVer[1]);
    security_note(data:"DataTrack System version " + dtsVer[1] +
                                       " was detected on the host");
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:dtsVer[1], exp:"^([0-9.]+)", base:"cpe:/a:magnoware:datatrack_system:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}

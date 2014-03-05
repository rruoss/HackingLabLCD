###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ocs_inventory_ng_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# OCS Inventory NG Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# updated by Madhuri D <dmadhuri@secpod.com> on 2011-11-15
#  - To detect the newer versions
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
tag_summary = "This script finds the installed OCS Inventory NG version and saves
  the result in KB.";

if(description)
{
  script_id(902058);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("OCS Inventory NG Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of OCS Inventory NG in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902058";
SCRIPT_DESC = "OCS Inventory NG Version Detection";

ocsPort = get_http_port(default:80);
if(!ocsPort){
  exit(0);
}

foreach dir (make_list("/ocsreports", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir , "/index.php"), port:ocsPort);
  rcvRes = http_send_recv(port:ocsPort, data:sndReq);

  ## Confirm the application
  if(("OCS Inventory" >< rcvRes) && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    ocsVer = eregmatch(pattern:"Ver. (<?.>)?([0-9.]+).?(RC[0-9]+)?", string:rcvRes);
    if(!isnull(ocsVer[2]))
    {
      if(!isnull(ocsVer[3])){
        ocsVer = ocsVer[2] + "." + ocsVer[3];
      }
      else
        ocsVer = ocsVer[2];
    }

    ## Set the KB value
    tmp_version = ocsVer + " under " + dir;
    set_kb_item(name:"www/" + ocsPort + "/OCS_Inventory_NG",
               value:tmp_version);
    security_note(port:ocsPort, data:"OCS Inventory NG version " + ocsVer +
                    " running at location " + dir + " was detected on the host");

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:ocsinventory-ng:ocs_inventory_ng:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fcms_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Haudenschilt Family Connections CMS (FCMS) Version Detection
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
tag_summary = "This script detects the installed version of Haudenschilt Family
  Connections CMS (FCMS) and sets the result in KB.";

if(description)
{
  script_id(902309);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Haudenschilt Family Connections CMS (FCMS) Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of Haudenschilt Family Connections CMS (FCMS) in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902309";
SCRIPT_DESC = "Haudenschilt Family Connections CMS (FCMS) Version Detection";

## GET HTTP port
cmsPort = get_http_port(default:80);
if(!cmsPort){
  exit(0);
}

foreach dir (make_list("/fcms", "/FCMS", "/", cgi_dirs()))
{
  ## Send and receive response
  sndReq = http_get(item:string(dir, "/index.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  ## Check application is Family Connections CMS
  if("- powered by Family Connections" >< rcvRes)
  {
    ## Grep the version
    cmsVer = eregmatch(pattern:"Family Connections ([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      ## Set the KB item
      tmp_version = cmsVer[1] + " under " + dir;
      set_kb_item(name:"www/" + cmsPort + "/FCMS",
                    value:tmp_version);
      security_note(data:"Family Connections version " + cmsVer[1] +
                   " running at location " + dir + " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:haudenschilt:family_connections_cms:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nakid_cms_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Nakid CMS Version Detection
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
tag_summary = "This script finds the running Nakid CMS version and
  saves the result in KB.";

if(description)
{
  script_id(902083);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_name("Nakid CMS Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Nakid CMS in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902083";
SCRIPT_DESC = "Nakid CMS Version Detection";

## Get HTTP Port
ncPort = get_http_port(default:80);
if(!ncPort){
  exit(0);
}

if(!get_port_state(ncPort)){
  exit(0);
}

foreach path (make_list("/nakid", "/Nakid", "/", cgi_dirs()))
{
  ## Send and Recieve the respose
  sndReq = http_get(item:string(path, "/index.php"), port:ncPort);
  rcvRes = http_send_recv(port:ncPort, data:sndReq);

  ## Confirm it is Nakid CMS
  if(">Nakid CMS<" >< rcvRes)
  {
    ncVer = eregmatch(pattern:"> v.([0-9.]+)", string:rcvRes);
    if(ncVer[1] != NULL){
     
      tmp_version = ncVer[1] + " under " + path;
      set_kb_item(name:"www/" + ncPort + "/Nakid/CMS/Ver", value:tmp_version);
      security_note(data:"Nakid CMS version " + ncVer[1] +
                         " running at location " + path +
                         " was detected on the host", port:ncPort);
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:jeffkilroy:nakid_cms:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

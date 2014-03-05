###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_fuzzylime_cms_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Fuzzylime(cms) Version Detection
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
tag_summary = "This script detects the installed version of Fuzzylime(cms)
  and sets the version in KB.";

if(description)
{
  script_id(900583);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Fuzzylime(cms) Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of Fuzzylime(cms)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900583";
SCRIPT_DESC = "Fuzzylime(cms) Version Detection";

cmsPort = get_http_port(default:80);
if(!cmsPort){
  cmsPort = 80;
}
if(!get_port_state(cmsPort)){
  exit(0);
}

foreach dir (make_list("/cms", "/", "/docs", "/fuzzylime", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  if("fuzzylime (cms)" ><rcvRes)
  {
    sndReq = http_get(item:string(dir, "/admin/includes/ver.inc.php"), port:cmsPort);
    rcvRes = http_send_recv(port:cmsPort, data:sndReq);
    if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
    {
      cmsVer = egrep(pattern:"^([0-9]\.[0-9]+)", string:rcvRes);
      cmsVer = eregmatch(pattern:"([0-9.]+[a-z]?)", string:cmsVer);
    }
    else
    {
      sndReq = http_get(item:string(dir, "/docs/readme.txt"), port:cmsPort);
      rcvRes = http_send_recv(port:cmsPort, data:sndReq);
      if("fuzzylime (cms)" >< rcvRes){
        cmsVer = eregmatch(pattern:"v([0-9.]+)", string:rcvRes);
      }
    }
    if(cmsVer[1] != NULL){

        tmp_version = cmsVer[1] + " under " + dir;
        set_kb_item(name:"www/"+ cmsPort + "/Fuzzylime(cms)",
                    value:tmp_version);
        security_note(data:"Fuzzylime(cms) Version " + cmsVer[1] +
                 " running at location " + dir +  " was detected on the host");
   
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:fuzzylime:fuzzylime_cms:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
 }
}

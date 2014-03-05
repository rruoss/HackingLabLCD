##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vmware_springsource_tc_server_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# Vmware SpringSource tc Server Version Detection
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
################################################################################

include("revisions-lib.inc");
tag_summary = "This script detects the installed version of Vmware SpringSource tc
  Server and sets the result in KB.";

if(description)
{
  script_id(902187);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Vmware SpringSource tc Server Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the Version of Vmware SStc Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902187";
SCRIPT_DESC = "Vmware SpringSource tc Server Version Detection";

sstcPort = get_http_port(default:8080);
if(!sstcPort){
  sstcPort = 8080;
}

if(!get_port_state(sstcPort)){
  exit(0);
}

foreach dir (make_list("/", "/myserver", "/SStc", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.html"), port:sstcPort);
  rcvRes = http_send_recv(port:sstcPort, data:sndReq);

  if("<title>SpringSource tc Server</title>"  >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/WEB-INFO/web.xml"), port:sstcPort);
    rcvRes = http_send_recv(port:sstcPort, data:sndReq);

    if( "SpringSource tc Server runtime" >< rcvRes)
    {

      sstcVer = eregmatch(pattern:"tc Server runtime/(([0-9.]+).?([A-Za-z0-9-]+))?",
                          string:rcvRes);
      sstcVer = ereg_replace(pattern:"-", replace:".", string:sstcVer[1]);
      if(sstcVer != NULL)
      {
        tmp_version = sstcVer + " under " + dir;
        set_kb_item(name:"www/"+ sstcPort + "/Vmware/SSTC/Runtime",
                  value:tmp_version);
        security_note(data:"SpringSource tc Server Version " + sstcVer +
               " running at location " + dir +  " was detected on the host");

        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:vmware:tc_server:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
    }
  }
}

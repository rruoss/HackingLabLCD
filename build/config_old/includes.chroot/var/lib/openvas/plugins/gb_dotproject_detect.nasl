###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotproject_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# dotProject Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script detects the installed version of dotProject and
  sets the version in KB.";

if(description)
{
  script_id(800564);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("dotProject Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of dotProject");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800564";
SCRIPT_DESC = "dotProject Version Detection";

wwwPort = get_http_port(default:80);
if(!wwwPort){
  exit(0);
}

foreach dir (make_list("/dotproject", "/dotProject", "/Dotproject", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:wwwPort);
  rcvRes = http_send_recv(port:wwwPort, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if("dotProject" >< rcvRes)
  {
    version = eregmatch(pattern:"Version ([0-9.]+)(rc[0-9])?", string:rcvRes);
    if(version[1] != NULL)
    {
      if(version[2] != NULL){
        dotVer = version[1] + "." + version[2];
      }
      else
        dotVer = version[1];

        tmp_version = dotVer + " under " + dir;
        set_kb_item(name:"www/" + wwwPort + "/dotProject", value:tmp_version);
        security_note(data:"Dot Project version " + dotVer + " running at location "
                         + dir + " was detected on the host");
   
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:dotproject:dotproject:");
        if(!isnull(cpe))
           register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
    exit(0);
  }
}

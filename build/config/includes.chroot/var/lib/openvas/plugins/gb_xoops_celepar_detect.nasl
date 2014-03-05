###############################################################################
# Openvas Vulnerability Test
# $Id: gb_xoops_celepar_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Xoops Celepar Version Detection
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the gnu general public license version 2
# (or any later version), as published by the free software foundation.
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
tag_summary = "This script is detects the installed version of Xoops Celepar
  and sets the result in KB.";

if(description)
{
  script_id(801152);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_name("Xoops Celepar Version Detection");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Xoops Celepar in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801152";
SCRIPT_DESC = "Xoops Celepar Version Detection";

## Get HTTP port
xoopsPort = get_http_port(default:80);
if(!xoopsPort){
  exit(0);
}

## Check for the Xoops Celepar
foreach dir (make_list("/xoopscelepar", "/" , cgi_dirs()))
{
  ## Send and recieve the response
  sndReq = http_get(item:string(dir, "/index.php"), port:xoopsPort);
  rcvRes = http_send_recv(port:xoopsPort, data:sndReq);

  ## Confirm it's Xoops application installed
  if("200 OK" >< rcvRes && ">XOOPS Site" >< rcvRes)
  {
    celeparVer = eregmatch(pattern:">Powered by XOOPS ([0-9.]+)",
                           string:rcvRes);
    ## Set the kb item
    if(celeparVer[1] != NULL)
    {
      tmp_version = celeparVer[1] + " under " + dir;
      set_kb_item(name:"www/" + xoopsPort + "/XoopsCelepar",
                  value:tmp_version);
      security_note(data:"Xoops Celepar version " + celeparVer[1] +
                 " running at location " + dir +  " was detected on the host");
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:alexandre_amaral:xoops_celepar:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}

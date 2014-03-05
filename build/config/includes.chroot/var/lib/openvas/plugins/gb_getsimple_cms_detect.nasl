###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# GetSimple CMS version detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This script finds the running GetSimple CMS version and saves
  the result in KB.";

if(description)
{
  script_id(801550);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("GetSimple CMS version detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of GetSimple CMS in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801550";
SCRIPT_DESC = "GetSimple CMS version detection";

## Get HTTP Port
cmsPort = get_http_port(default:80);
if(!cmsPort){
  exit(0);
}

foreach dir (make_list("/GetSimple", "/GetSimple_2.01" , cgi_dirs()))
{
  ## Send and Receive request
  sndReq = http_get(item:string(dir, "/index.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  ## Confirm application is GetSimple CMS
  if(">Powered by GetSimple<" >< rcvRes)
  {
    ## Grep the version
    cmsVer = eregmatch(pattern:"> Version ([0-9.]+)<" , string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      tmp_version = cmsVer[1] + " under " + dir;
      set_kb_item(name:"www/" + cmsPort + "/GetSimple_cms",
                value:tmp_version);
      security_note(data:"GetSimple version " + cmsVer[1] + " running at location "
                    + dir + " was detected on the host");
  
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:getsimple:getsimple:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

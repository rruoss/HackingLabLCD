###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pivot_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pivot Version Detection
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
tag_summary = "This script detects the installed version of Pivot and
  sets the result in KB.";

if(description)
{
  script_id(900578);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Pivot Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets the KB for the version of Pivot");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900578";
SCRIPT_DESC = "Pivot Version Detection";

pivotPort = get_http_port(default:80);
if(!pivotPort){
  pivotPort = 80;
}
if(!get_port_state(pivotPort)){
  exit(0);
}

foreach dir (make_list("/pivot", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/pivot/index.php"), port:pivotPort);
  rcvRes = http_send_recv(port:pivotPort, data:sndReq);

  if("Pivot" >< rcvRes)
  {
    ver = eregmatch(pattern:"Pivot - ([0-9]\.[0-9.]+ ?(alpha|beta|RC)?" +
                            " ?[0-9]?[a-z]?)?", string:rcvRes);
    pivotVer = ereg_replace(pattern:" ", replace:".", string:ver[1]);
    if(pivotVer != NULL)
    {
      tmp_version = pivotVer + " under " + dir;
      set_kb_item(name:"www/" + pivotPort + "/Pivot",
                value:tmp_version);
      security_note(data:"Pivot version " + pivotVer + " running at " +
                         "location " + dir +  " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:pivot:pivot:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

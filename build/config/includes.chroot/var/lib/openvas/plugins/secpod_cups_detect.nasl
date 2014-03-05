###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cups_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# CUPS Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of CUPS (Common UNIX
  Printing System) and sets the result in KB.";

if(description)
{
  script_id(900348);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("CUPS Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set KB for the version of CUPS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 631);
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900348";
SCRIPT_DESC = "CUPS Version Detection";

cupsPort = get_http_port(default:631);
if(!cupsPort){
  cupsPort = 631;
}

if(!get_port_state(cupsPort)){
  exit(0);
}

foreach dir (make_list("/", "/admin/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir), port:cupsPort);
  rcvRes = http_send_recv(port:cupsPort, data:sndReq);

  if("CUPS" >< rcvRes && egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    ver = eregmatch(pattern: "<TITLE>(Home|Administration) - CUPS ([0-9.]+)([a-z][0-9])?"+
                             "</TITLE>", string:rcvRes);
    if(ver[2] != NULL)
    {
      if(ver[3] != NULL){
        cupsVer = ver[2] + "." + ver[3];
      }
      else cupsVer = ver[2];

      set_kb_item(name:"www/"+ cupsPort + "/CUPS", value:cupsVer);
      security_note(data:"CUPS version " + cupsVer + " running at location " +
                                            dir + " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:cupsVer, exp:"^([0-9.]+\.[0-9])\.([a-z0-9]+)?", base:"cpe:/a:apple:cups:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

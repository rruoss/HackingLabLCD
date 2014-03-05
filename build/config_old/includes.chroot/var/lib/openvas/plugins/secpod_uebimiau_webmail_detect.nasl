###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_uebimiau_webmail_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Uebimiau Webmail Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c)2009 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the Uebimiau Webmail version and saves
  the result in KB.";

if(description)
{
  script_id(901023);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Uebimiau Webmail Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Uebimiau Webmail in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901023";
SCRIPT_DESC = "Uebimiau Webmail Version Detection";

uwebPort = get_http_port(default:80);
if(!uwebPort){
  exit(0);
}

foreach path (make_list("/", "/uebimiau", "/webmail",  cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php"), port:uwebPort);
  rcvRes = http_send_recv(port:uwebPort, data:sndReq);

  if("Uebimiau Webmail" >< rcvRes)
  {
    uwebVer = eregmatch(pattern:"Webmail v(([0-9.]+)(-[0-9.]+)?)", string:rcvRes);
    if(uwebVer[1] != NULL)
    {
      uwebVer = ereg_replace(pattern:"-", string:uwebVer[1], replace: ".");
      tmp_version = uwebVer + " under " + path;
      set_kb_item(name:"www/" + uwebPort + "/Uebimiau/Webmail", value:tmp_version);
      security_note(data:"Uebimiau Webmail version " + uwebVer +
                         " running at location " + path +
                         " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:uebimiau:uebimiau:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

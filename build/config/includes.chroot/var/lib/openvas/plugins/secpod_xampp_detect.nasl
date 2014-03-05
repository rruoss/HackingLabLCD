###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xampp_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# XAMPP Version Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script finds the installed XAMPP version and saves the
  version in KB.";

if(description)
{
  script_id(900526);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("XAMPP Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the Version of XAMPP in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900526";
SCRIPT_DESC = "XAMPP Version Detection";

xamppPort = get_http_port(default:80);;
if(!xamppPort){
  exit(0);
}

foreach path (make_list("/", "/xampp", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php"), port:xamppPort);
  rcvRes = http_keepalive_send_recv(port:xamppPort, data:sndReq);

  if("XAMPP" >!< rcvRes)
  {
    sndReq = http_get(item:string(dir,"/start.php"), port:xamppPort);
    rcvRes = http_keepalive_send_recv(port:xamppPort, data:sndReq);
  }

  if("XAMPP" >< rcvRes)
  {
    xamppVer = eregmatch(pattern:"XAMPP.* ([0-9.]+)", string:rcvRes);
    if(xamppVer[1] != NULL)
    {
      set_kb_item(name:"www/" + xamppPort + "/XAMPP", value:xamppVer[1]);
      security_note(data:"XAMPP version " + xamppVer[1] + " running at " +
                         "location " + path +  " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:xamppVer[1], exp:"^([0-9.]+)", base:"cpe:/a:apachefriends:xampp:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
    exit(0);
  }
}

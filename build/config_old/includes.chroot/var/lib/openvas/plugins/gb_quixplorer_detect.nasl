###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_quixplorer_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# QuiXplorer Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script finds the installed QuiXplorer Version and saves the
  version in KB.";

if(description)
{
  script_id(800630);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:46:51 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("QuiXplorer Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_family("Service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_summary("Set Version of QuiXplorer in KB");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800630";
SCRIPT_DESC = "QuiXplorer Version Detection";

quixplorerPort = get_http_port(default:80);

if(!get_port_state(quixplorerPort)){
  exit(0);
}

foreach dir (make_list("/quixplorer", "/quixplore", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:quixplorerPort);
  rcvRes = http_send_recv(port:quixplorerPort, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if(egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes) &&
     egrep(pattern:"QuiXplorer", string:rcvRes))
  {
    quixplorerVer = eregmatch(pattern:"QuiXplorer (([0-9.]+)(BETA)?)", string:rcvRes);

    if(quixplorerVer[1] != NULL)
    {
      tmp_version = quixplorerVer[1] + " under " + dir;
      set_kb_item(name:"www/"+ quixplorerPort + "/QuiXplorer", value:tmp_version);
      security_note(data:"QuiXplorer version " + quixplorerVer[1] + 
                    " running at location " + dir + " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?", base:"cpe:/a:claudio_klingler:quixplorer:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

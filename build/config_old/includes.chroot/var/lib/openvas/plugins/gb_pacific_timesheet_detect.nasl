###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pacific_timesheet_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# Pacific Timesheet Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_summary = "This script is detects the installed version of Pacific Timesheet
  and sets the result in KB.";

if(description)
{
  script_id(800180);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Pacific Timesheet Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Pacific Timesheet in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800180";
SCRIPT_DESC = "Pacific Timesheet Version Detection";

## Get Pacific Timesheet port
pacificTSPort = get_http_port(default:80);
if(!pacificTSPort){
  pacificTSPort = 80;
}

## Check Port status
if(!get_port_state(pacificTSPort)){
  exit(0);
}

foreach path (make_list("/", "/timesheet", cgi_dirs()))
{
  ## Send the request and Recieve the response
  sndReq = http_get(item: path + "/about-show.do", port:pacificTSPort);
  rcvRes = http_send_recv(port:pacificTSPort, data:sndReq);

  ## Confirm application is Pacific Timesheet
  if(">About Pacific Timesheet<" >< rcvRes)
  {
    ## Get Pacific Timesheet Version
    pacificTSVer = eregmatch(pattern:">Version ([0-9.]+) [Bb][Uu][Ii][Ll][Dd]"+
                                     " ([0-9]+)</", string:rcvRes);

    if(pacificTSVer[1] != NULL && pacificTSVer[2] != NULL)
    {
      pacificTSVer = pacificTSVer[1] + "." + pacificTSVer[2];
      tmp_version = pacificTSVer + " under " + path;
      set_kb_item(name:"www/" + pacificTSPort + "/pacificTimeSheet/Ver",
                        value:tmp_version);
      security_note(data:"Pacific Timesheet version " + pacificTSVer +
                         " running at location " + path +
                         " was detected on the host", port:pacificTSPort);
      
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:pacifictimesheet:pacific_timesheet:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      exit(0);
    }
  }
}

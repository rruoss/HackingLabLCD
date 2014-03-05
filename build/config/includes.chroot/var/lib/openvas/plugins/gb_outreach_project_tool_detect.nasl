###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_outreach_project_tool_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Outreach Project Tool Version Detection (OPT)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This script finds the installed Outreach Project Tool version and
  saves the result in KB.";

if(description)
{
  script_id(801069);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Outreach Project Tool Version Detection (OPT)");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Outreach Project Tool(OPT) in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801069";
SCRIPT_DESC = "Outreach Project Tool Version Detection (OPT)";

optPort = get_http_port(default:80);
if(!optPort){
  exit(0);
}

foreach path(make_list("/", "/OPT127MAX/opt", "/opt", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php?OPT_Session=" +
                                      " OpenVAS_Req"), port:optPort);
  rcvRes = http_send_recv(port:optPort, data:sndReq);
  if("<title>Outreach Project Tool Login</title>" >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/include/init_OPT_lib.txt"), port:optPort);
    rcvRes = http_send_recv(port:optPort, data:sndReq);
    if(!isnull(rcvRes) && (optVer = egrep(pattern:"CRM_ver.*", string:rcvRes)))
    {
      optVer = eregmatch(pattern:"([0-9.]+)", string:optVer);
      if(optVer[1] != NULL)
      {
       tmp_version = optVer[1] + " under " + path;
       set_kb_item(name:"www/" + optPort + "/OPT", value:tmp_version);
       security_note(data:"Outreach Project Tool version " + optVer[1] +
                      " running at location " + path + " was detected on the host");
   
        ## build cpe and store it as host_detail
#        cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:lanifex:outreach_project_tool:");
#        if(!isnull(cpe))
           register_host_detail(name:"App", value:"cpe:/a:lanifex:outreach_project_tool:"+optVer[1], nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      }
    }
  }
}

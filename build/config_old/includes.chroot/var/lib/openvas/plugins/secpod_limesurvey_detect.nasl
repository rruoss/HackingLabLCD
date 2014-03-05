###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_limesurvey_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# LimeSurvey Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_summary = "The script detects the installed version of LimeSurvey on remote
  host and saves the result in KB.";

if(description)
{
  script_id(900352);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-26 15:05:11 +0200 (Tue, 26 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("LimeSurvey Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Sets for the version of LimeSurvey in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900352";
SCRIPT_DESC = "LimeSurvey Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
surveyPort = get_http_port(default:80);
if(!surveyPort){
  surveyPort = 80;
}

if(!get_port_state(surveyPort)){
  exit(0);
}

foreach dir (make_list("/limesurvey", "/phpsurveyor", "/survey", "/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/admin/admin.php"), port:surveyPort);
  rcvRes = http_send_recv(port:surveyPort, data:sndReq);

  # Set KB for the version of LimeSurvey Product
  if("<title>LimeSurvey</title>" >< rcvRes)
  {
    req = http_get(item:string(dir, "/docs/release_notes_and_upgrade" +
                                    "_instructions.txt"),
                               port:surveyPort);
    res = http_send_recv(port:surveyPort, data:req);

    if(res != NULL)
    {
      surveyVer = eregmatch(pattern:"LimeSurvey v([0-9.RCa-z]+)\+?!([^.0-9]|$)",
                            string:res);
      if(surveyVer[1] != NULL)
      {
        tmp_version = surveyVer[1] + " under " + dir;
        set_kb_item(name:"www/" + surveyPort + "/LimeSurvey",
                    value:tmp_version);
        security_note(data:"LimeSurvey version " + surveyVer[1] +
                " running at location " + dir +  " was detected on the host");

        ## build cpe and store it as host detail
        register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?",tmpBase:"cpe:/a:limesurvey:limesurvey:");

      }
    }
  }

  # Set KB for the version of PHPSurveyor or Surveyor Product
  # Note: PHPSurveyor or Surveyor are the product name of old LimeSurvey
  if("<title>PHPSurveyor</title>" >< rcvRes ||
     "<title>Surveyor</title>" >< rcvRes)
  {
    surveyorVer = eregmatch(pattern:"Ver(sion)? ([0-9.RCa-z]+)([^.0-9]|$)",
                             string:rcvRes);
    if(surveyorVer[2] != NULL)
    {
      tmp_version = surveyorVer[2] + " under " + dir;
      set_kb_item(name:"www/" + surveyPort + "/LimeSurvey",
                  value:tmp_version);
      security_note(data:"LimeSurvey version " + surveyorVer[2] + 
                " running at location " + dir +  " was detected on the host");

      ## build cpe and store it as host detail
      register_cpe(tmpVers:tmp_version,tmpExpr:"^([0-9.]+\.[0-9])\.?([a-z0-9]+)?",tmpBase:"cpe:/a:limesurvey:limesurvey:");

    }
  }
}

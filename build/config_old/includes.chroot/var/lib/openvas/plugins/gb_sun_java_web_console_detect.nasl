###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_web_console_detect.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java Web Console Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_summary = "This script detects the installed version of Java Web Console
  and sets the result in KB.";

if(description)
{
  script_id(800825);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Sun Java Web Console Version Detection");
  desc = "

  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of Sun Java Web Console in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("openvas-https.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800825";
SCRIPT_DESC = "Sun Java Web Console Version Detection";

# Default HTTPS port
jwcPort = 6789;
if(!get_port_state(jwcPort)){
  exit(0);
}

# Send Request for Login page
sndReq1 = string("GET /console/faces/jsp/login/BeginLogin.jsp", " HTTP/1.1\r\n",
                 "Host: ", get_host_name(),":", jwcPort, "\r\n",
                 "User-Agent: Mozilla/5.0\r\n");
rcvRes1 = https_req_get(port:jwcPort, request:sndReq1);

# Check for Login Page with proper Response
if(rcvRes1 =~ "<title>Log In - Sun Java\(TM\) Web Console<" &&
   egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes1))
{
  # Grep the Version Page Path in Login Page
  jspPath = eregmatch(pattern:"versionWin = window.open\('([a-zA_Z0-9/_.]+)'",
                      string:rcvRes1);

  # Send Request for Version Page
  sndReq2 = string("GET ", jspPath[1], " HTTP/1.1\r\n",
                   "Host: ", get_host_name(), ":", jwcPort, "\r\n",
                   "User-Agent: Mozilla/5.0\r\n");
  rcvRes2 = https_req_get(port:jwcPort, request:sndReq2);

  # Check for Version Page with proper Response
  if(rcvRes2 =~ ">Display Product Version - Sun Java\(TM\) Web Console<" &&
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes2))
  {
    # Grep and Set KB for Java Web Console version
    jwcVer = eregmatch(pattern:">([0-9]\.[0-9.]+)<", string:rcvRes2);
    if(jwcVer[1] != NULL)
    {
      set_kb_item(name:"Sun/JavaWebConsole/Ver", value:jwcVer[1]);
      security_note(data:"Sun Java Web Console version " + jwcVer[1] +
                         " was detected on the host");
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:jwcVer[1], exp:"^([0-9.]+)", base:"cpe:/a:sun:java_web_console:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    }
  }
}

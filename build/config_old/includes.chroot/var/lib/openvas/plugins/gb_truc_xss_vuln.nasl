###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_truc_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Tracking Requirements And Use Cases Cross Site Scripting vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow the attackers to inject arbitrary web script or
  HTML via the error parameter in the context of an affected site.
  Impact Level: Application";
tag_affected = "Tracking Requirements and Use Cases (TRUC) version 0.11.0.";
tag_insight = "The flaw is due to an input validation error in the 'login_reset_password_page.php'
  script when processing data passed via the 'error' parameter.";
tag_solution = "No solution or patch is available as of 01st April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.ohloh.net/p/truc";
tag_summary = "The host is running Tracking Requirements and Use Cases and is prone to
  cross site scripting vulnerability";

if(description)
{
  script_id(800745);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-1095");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Tracking Requirements And Use Cases Cross Site Scripting vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://vul.hackerjournals.com/?p=7357");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0491");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Tracking Requirements and Use Cases");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

# Check TRUC is running
trucPort = get_http_port(default:80);
if(!trucPort){
  exit(0);
}

foreach path (make_list("/", "/truc", "/Truc", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/login.php"), port:trucPort);
  rcvRes = http_send_recv(port:trucPort, data:sndReq);
  if("TRUC" >< rcvRes)
  {
    # Get the version from login.php
    sndReq = http_get(item:string(path, "/login.php"), port:trucPort);
    rcvRes = http_send_recv(port:trucPort, data:sndReq);
    if("TRUC" >< rcvRes)
    {
      trucVer = eregmatch(pattern:"TRUC ([0-9.]+)", string:rcvRes);
      if(trucVer[1] != NULL)
      {
        # Checking for TRUC Version <= 0.11.0
        if(version_is_equal(version:trucVer[1], test_version:"0.11.0")){
          security_warning(trucPort);
        }
      }
    }
  }
}

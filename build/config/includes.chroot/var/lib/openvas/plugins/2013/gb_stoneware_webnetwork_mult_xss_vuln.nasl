###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_stoneware_webnetwork_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Stoneware webNetwork Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site.
  Impact Level: Application";

tag_affected = "Stoneware WebNetwork 6.1 before SP1";
tag_insight = "Multiple flaws exists because application does the validate,
  - 'blogName' parameter passed to blog.jsp and blogSearch.jsp
  - 'calendarType' and 'monthNumber' parameters passed to calendar.jsp
  - 'flag' parameter passed to swDashboard/ajax/setAppFlag.jsp";
tag_solution = "Upgrade to Stoneware webNetwork 6.1 SP1 or later,
  For updates refer to http://www.stone-ware.com/webnetwork";
tag_summary = "This host is installed with Stoneware webNetwork and is prone to
  multiple cross-site scripting vulnerabilities.";

if(description)
{
  script_id(803326);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-4352");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-06 11:46:39 +0530 (Wed, 06 Mar 2013)");
  script_name("Stoneware webNetwork Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/88359");
  script_xref(name : "URL" , value : "http://stoneware-docs.s3.amazonaws.com/Bulletins/Security%20Bulletin%206_1_0.pdf");
  script_xref(name : "URL" , value : "http://infosec42.blogspot.in/2012/10/stoneware-webnetwork-61-reflective-xss.html");

  script_description(desc);
  script_summary("Check if Stoneware webNetwork is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Send and Receive the response
req = http_get(item:string(dir,"/"),  port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

##Confirm the application
if('>Stoneware' >< res)
{
  ## Construct Attack Request
  url = dir + '/community/calendar.jsp?calendarType=>'+
           '<script>alert(document.cookie)</script>';

  ## Check the response to confirm vulnerability
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern: "<script>alert\(document.cookie\)</script>",
     extra_check: "Stoneware"))
  {
    security_warning(port);
    exit(0);
  }
}
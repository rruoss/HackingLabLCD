###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_level_four_storefront_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wordpress Level Four Storefront Plugin SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data.
  Impact Level: Application";

tag_affected = "Wordpress Level Four Storefront Plugin";
tag_insight = "The flaw is due to improper validation of user-supplied input to the
  getsortmanufacturers.php script via id parameter.";
tag_solution = "No solution or patch is available as of 26th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to www.levelfourstorefront.com";
tag_summary = "This host is installed with Wordpress Level Four Storefront Plugin
  and is prone to sql injection vulnerability.";

if(description)
{
  script_id(803449);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-26 15:01:02 +0530 (Tue, 26 Mar 2013)");
  script_name("Wordpress Level Four Storefront Plugin SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120950/wplevelfourstorefront-sql.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-level-four-storefront-sql-injection");

  script_description(desc);
  script_summary("Check if WordPress Level Four Storefront Plugin is vulnerable sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
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
include("version_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";

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

## Get WordPress Location
if(!dir = get_dir_from_kb(port:port, app:"WordPress")){
  exit(0);
}

## Construct the Attack Request
url = dir + "/wp-content/plugins/levelfourstorefront/getsortmanufacturers.php?id=-1'[SQLi]--";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url,
        pattern:"mysql_query\(\).*getsortmanufacturers.php"))
{
  security_hole(port);
  exit(0);
}


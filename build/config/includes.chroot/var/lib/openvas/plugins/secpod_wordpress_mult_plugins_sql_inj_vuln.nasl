###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_mult_plugins_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress Multiple Plugins SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to conduct SQL injection
  attacks.
  Impact Level: Application";
tag_affected = "WordPress Yolink Search version 1.1.4
  WordPress Crawl Rate Tracker Plugin version 2.0.2";
tag_insight = "Refer the references, for information about vulnerability.";
tag_solution = "No solution or patch is available as of 17th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/crawlrate-tracker/
                     http://wordpress.org/extend/plugins/yolink-search/";
tag_summary = "This host is running WordPress with multiple plugins and is prone and is
  prone to SQL injection vulnerabilities";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902755";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_bugtraq_id(49382, 49381);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-17 14:31:04 +0530 (Thu, 17 Nov 2011)");
  script_name("WordPress Multiple Plugins SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45801");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69504");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17757/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17755/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104610/wpyolink-sql.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/104608/wpcrawlratetracker-sql.txt");

  script_description(desc);
  script_summary("Check if WordPress plugins are prone to SQL injection vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Make list of vulnerable pages
pages = make_list("/wp-content/plugins/crawlrate-tracker/sbtracking-chart-data.php?chart_data=1&page_url='",
                  "/wp-content/plugins/yolink-search/includes/bulkcrawl.php?page='");

foreach page (pages)
{
  if(http_vuln_check(port:port, url: dir + page, pattern: "<b>" +
                 "Warning</b>:  Invalid argument supplied for foreach\(\)") ||
  (http_vuln_check(port:port, url:dir + page, pattern:"You have an error in " +
                        "your SQL syntax;")))
  {
    security_hole(port);
    exit(0);
  }
}

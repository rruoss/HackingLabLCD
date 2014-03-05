###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpbb_mypage_plugin_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpBB MyPage Plugin 'id' Parameter SQL Injection Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "phpBB Mypage plugin version 0.2.3 and prior";
tag_insight = "The flaw is caused by improper validation of user-supplied input sent via
  the 'id' parameter to 'mypage.php', which allows attackers to manipulate SQL
  queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 13th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.phpbb.com/";
tag_summary = "This host is running phpBB MyPage plugin and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(902641);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-13 12:30:52 +0530 (Tue, 13 Dec 2011)");
  script_name("phpBB MyPage Plugin 'id' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.phpbbexploit.com/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18212/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107586/mypage-sql.txt");
  script_xref(name : "URL" , value : "http://www.crackhackforum.com/thread-188498-post-344690.html#pid344690");

  script_description(desc);
  script_summary("Check if phpBB MyPage Plugin is vulnerable to SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpbb_detect.nasl");
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

##
## The script code starts here
##

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get phpBB Installed Location
if(!dir = get_dir_from_kb(port:port, app:"phpBB")){
  exit(0);
}

## Construct the Attack Request
url =  dir + "/mypage.php?id=1'";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"You have an error" +
                      " in your SQL syntax;", check_header: TRUE)){
  security_hole(port);
}

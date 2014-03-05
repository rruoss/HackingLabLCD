##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_techfolio_comp_catid_param_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! Techfolio Component 'catid' Parameter SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to cause SQL Injection attack and
  gain sensitive information.
  Impact Level: Application.";
tag_affected = "Joomla! Techfolio Component Version 1.0";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'catid' parameter to index.php (when 'option' is set to 'com_techfolio'
  and 'view' is set to 'techfoliodetail'), which allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.";
tag_solution = "No solution or patch is available as of 4th November 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.techdeluge.com/joomla-component/com_techfolio.zip";
tag_summary = "This host is running Joomla! Techfolio component and is prone to
  SQL injection vulnerability.";

if(description)
{
  script_id(802267);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-04 12:12:12 +0530 (Fri, 04 Nov 2011)");
  script_bugtraq_id(50422);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla! Techfolio Component 'catid' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71029");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18042/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/106353/joomlatechfolio-sql.txt");

  script_description(desc);
  script_summary("Check if Joomla! Techfolio component is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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
url = dir + "/index.php?option=com_techfolio&view=techfoliodetail&catid=1'";

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
                   pattern:"Invalid argument supplied for foreach\(\)",
                   extra_check:">Warning<")){
  security_hole(port);
}

##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_xshop_sql_inj_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Joomla com_x-shop 'idd' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "Joomla x-shop component";
tag_insight = "The flaw is due to an input passed via the 'idd' parameter to
  'index.php' (when 'option' is set to 'com_x-shop' & 'action' is set to
  'artdetail') is not properly sanitised before being used in a SQL query.";
tag_solution = "No solution or patch is available as of 12th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://extensions.joomla.org/extensions/";
tag_summary = "This host is running Joomla x-shop component and is prone to SQL
  injection vulnerability.";

if(description)
{
  script_id(802706);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52077);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-12 19:12:57 +0530 (Mon, 12 Mar 2012)");
  script_name("Joomla com_x-shop 'idd' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/17540");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73332");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52077/info");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109938/Joomla-X-Shop-SQL-Injection.html");

  script_description(desc);
  script_summary("Check if Joomla x-shop component is vulnerable to SQL injection attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Variable Initialization
joomlaPort = 0;
joomlaDir = "";
url = "";

## Get the port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:joomlaPort)){
  exit(0);
}

## Get the application directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Construct attack request
url = string(joomlaDir, "/index.php?option=com_x-shop&action=artdetail&idd='");

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, pattern:">:  mysql_fetch_row" +
       "\(\): supplied argument is not a valid MySQL result",
       check_header:TRUE)) {
  security_hole(joomlaPort);
}
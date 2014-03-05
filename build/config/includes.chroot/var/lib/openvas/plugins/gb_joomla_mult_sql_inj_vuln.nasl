###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_mult_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Joomla! Multiple SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "Joomla! versions 1.5.x before 1.5.22";
tag_insight = "The flaws are caused by improper validation of user-supplied input via the
  'filter_order' and 'filter_order_Dir' parameters to 'index.php', which allows
  attacker to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to Joomla! 1.5.22 or later,
  For updates refer to http://www.joomla.org/download.html";
tag_summary = "The host is running Joomla! and is prone to multiple SQL injection
  vulnerabilities.";

if(description)
{
  script_id(801829);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_cve_id("CVE-2010-4166", "CVE-2010-4696");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Joomla! Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42133");
  script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");
  script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");
  script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/joomla/core/1.5.21/sql_injection/sqli_(filter_order_Dir)_front.jpg");

  script_description(desc);
  script_summary("Determine if Joomla! is prone to SQL Injection Vulnerability");
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

## Get Joomla Directory
if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

## Construct the Attack Request
url = string(dir, "/index.php?option=com_weblinks&view=category&id=2:joomla" +
             "-specific-links&limit=10&filter_order_Dir=&filter_order=%00");

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, pattern:'mysql_num_rows(): supplied' +
                   'argument is not a valid MySQL result resource',
                   check_header: TRUE)){
  security_hole(port);
}

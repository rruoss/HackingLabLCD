##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_quick_arcade_sql_injection_n_xss_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# PHP Quick Arcade SQL Injection and Cross Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to steal cookie-based authentication
  credentials, compromise the application, access or modify data.
  Impact Level: Application.";
tag_affected = "PHP-Quick-Arcade version 3.0.21 and prior.";
tag_insight = "The flaws are due to:
  - Input validation errors in the 'Arcade.php' and 'acpmoderate.php' scripts
    when processing the 'phpqa_user_c' cookie or the 'id' parameter, which could
    be exploited by malicious people to conduct SQL injection attacks.
  - Input validation error in the 'acpmoderate.php' script when processing the
   'serv' parameter, which could allow cross site scripting attacks.";
tag_solution = "No solution or patch is available as of 16th, June 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://quickarcade.jcink.com/?p=download";
tag_summary = "This host is running PHP Quick Arcade and is prone to SQL injection
  and cross site scripting Vulnerabilities.";

if(description)
{
  script_id(801364);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-1661", "CVE-2010-1662");
  script_bugtraq_id(39733);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("PHP Quick Arcade SQL Injection and Cross Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12416/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1013");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1004-exploits/phpquickarcade-sqlxss.txt");

  script_description(desc);
  script_summary("Check version of PHP Quick Arcade");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_php_quick_arcade_detect.nasl");
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

## Get HTTP Port
phpqaPort = get_http_port(default:80);
if(!phpqaPort){
  exit(0);
}

## Get the version from KB
phpqaVer = get_kb_item("www/" + phpqaPort + "/PHP-Quick-Arcade");
if(!phpqaVer){
  exit(0);
}

phpqaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phpqaVer);
if(isnull(phpqaVer[1])){
  exit(0);
}

## Check the version of PHP Quick Arcade
if(version_is_less_equal(version:phpqaVer[1], test_version:"3.0.21")){
  security_hole(phpqaPort);
}

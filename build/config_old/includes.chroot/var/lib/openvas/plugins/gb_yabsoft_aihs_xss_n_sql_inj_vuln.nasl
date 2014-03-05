###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_yabsoft_aihs_xss_n_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# YABSoft AIHS Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers to conduct cross-site
  scripting and SQL injection attacks.
  Impact Level: Application.";
tag_affected = "YABSoft AIHS version 2.3 and prior on all running platform.";
tag_insight = "The flaws are due to:
  - Input passed to the 'gal' parameter in 'gallery_list.php' is not properly
    sanitised before being used in SQL queries.
  - Input passed to the 'text' parameter in 'search.php' is not properly
    sanitised before being returned to the user.";
tag_solution = "No solution or patch is available as of 15th December, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://yabsoft.com/aihs-feature.php";
tag_summary = "The host is running YABSoft AIHS and is prone to Cross-Site Scripting
  and SQL Injection vulnerabilities";

if(description)
{
  script_id(801092);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4266", "CVE-2009-1032");
  script_bugtraq_id(37233, 34176);
  script_name("YABSoft AIHS Cross Site Scripting and SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34366");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49316");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54582");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10336");

  script_description(desc);
  script_summary("Check the version of YABSoft AIHS and XSS attack string");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_yabsoft_aihs_detect.nasl");
  script_family("Web application abuses");
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

aihsPort = get_http_port(default:80);
if(!aihsPort){
  exit(0);
}

aihsVer = get_kb_item("www/" + aihsPort + "/YABSoft/AIHS");
if(!aihsVer){
  exit(0);
}

aihsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:aihsVer);
if(!safe_checks() && aihsVer[2] != NULL)
{
  request = http_get(item:aihsVer[2] + "/search.php?text=%3Cscript%3E"+
          "alert(123456)%3C/script%3E&dosearch=Search", port:aihsPort);
  response = http_send_recv(port:aihsPort, data:request);

  if("alert(123456)" >< response)
  {
    security_hole(aihsPort);
    exit(0);
  }
}

if(aihsVer[1] != NULL)
{
  if(version_is_less_equal(version:aihsVer[1], test_version:"2.3")){
    security_hole(aihsPort);
  }
}

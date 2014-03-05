###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sqlitemanager_mult_xss_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# SQLiteManager 'dbsel' And 'nsextt' Parameters Multiple XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "SQLiteManager version 1.2.4 and prior.";
tag_insight = "The flaws are due to improper validation of user-supplied input via
  the 'dbsel' or 'nsextt' parameters to index.php or main.php script, which
  allows attacker to execute arbitrary HTML and script code on the user's
  browser session in the security context of an affected site.";
tag_solution = "No solution or patch is available as of 04th January, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sqlitemanager.org/index.php";
tag_summary = "The host is running SQLiteManager and is prone to multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(802373);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5105");
  script_bugtraq_id(51294);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-06 13:17:25 +0530 (Fri, 06 Jan 2012)");
  script_name("SQLiteManager 'dbsel' And 'nsextt' Parameters Multiple XSS Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521126");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108393/sqlitemanager124-xss.txt");

  script_description(desc);
  script_summary("Check if SQLiteManager is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlitemanager_detect.nasl");
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

## Get the HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Get the version from KB
dir = get_dir_from_kb(port:port,app:"SQLiteManager");
if(!dir){
  exit(0);
}

## Construct the Attack Request
url = dir + "/main.php?dbsel=</script><script>alert(document.cookie)</script>";

## Send XSS attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"</script><script>alert\(" +
                               "document.cookie\)</script>")){
  security_warning(port);
}

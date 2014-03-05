###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_frontaccounting_mult_sql_inj_vuln_2.nasl 15 2013-10-27 12:49:54Z jan $
#
# FrontAccounting Multiple SQL Injection Vulnerabilities
#
# Authors:
# Maneesh KB <kmaneesh@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to access and modify the backend
  database by conducting SQL injection attacks.
  Impact Level: Application";
tag_affected = "FrontAccounting versions prior to 2.2 RC";
tag_insight = "Input passed via multiple unspecified parameters to various scripts is not
  properly sanitised before being used in SQL queries. This can be exploited
  to manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to FrontAccounting version 2.2 RC
  http://frontaccounting.net/wb3/pages/download.php";
tag_summary = "This host is running FrontAccounting and is prone to multiple SQL Injection
  vulnerabilities.";

if(description)
{
  script_id(900258);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-30 15:32:46 +0100 (Mon, 30 Nov 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-4037", "CVE-2009-4046");
  script_name("FrontAccounting Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3223");
  script_xref(name : "URL" , value : "http://frontaccounting.net/wb3/pages/posts/release-2.2-rc104.php");

  script_description(desc);
  script_summary("Check for the version of FrontAccounting");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_frontaccounting_detect.nasl");
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

faPort = get_http_port(default:80);
if(!faPort){
  exit(0);
}

faVer = get_kb_item("www/" + faPort + "/FrontAccounting");
if(!faVer){
  exit(0);
}

# Check for FrontAccounting veriosn < 2.2 RC
faVer = eregmatch(pattern:"^(.+) under (/.*)$", string:faVer);
if(faVer[1])
{
  if(version_in_range(version:faVer[1], test_version:"2.2.0",
                                       test_version2:"2.2.Beta")){
    security_hole(faPort);
  }
}

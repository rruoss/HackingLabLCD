##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_csrf_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# HP System Management Homepage Cross-site Request Forgery Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to create an arbitrary
  user with administrative privileges, if a logged-in administrative user visits
  a malicious web site.
  Impact Level: Application";
tag_affected = "HP System Management Homepage (SMH) version 6.2.2.7";

tag_insight = "The flaw is due to certain actions via HTTP requests without
  performing any validity checks to verify the requests.";
tag_solution = "Upgrade to HP System Management Homepage (SMH) version 7.0 or later,
  For updates refer to http://h18000.www1.hp.com/products/servers/management/agents/index.html";
tag_summary = "This host is running HP System Management Homepage (SMH) and is
  prone to cross-site request forgery vulnerability.";

if(description)
{
  script_id(802758);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3846");
  script_bugtraq_id(52974);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-23 13:36:33 +0530 (Mon, 23 Apr 2012)");
  script_name("HP System Management Homepage Cross-site Request Forgery Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43012");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52974");

  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2381);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Variable Initialization
smhPort = "";
smhVer = "";

smhPort = get_http_port(default:2381);
if(!get_port_state(smhPort)){
  exit(0);
}

## Get HP SMH version from KB
smhVer = get_kb_item("www/" + smhPort+ "/HP/SMH");
if(!smhVer){
  exit(0);
}

## Check HP SMH version is equal to 6.2.2.7
if(version_is_equal(version:smhVer, test_version:"6.2.2.7")){
  security_hole(smhPort);
}

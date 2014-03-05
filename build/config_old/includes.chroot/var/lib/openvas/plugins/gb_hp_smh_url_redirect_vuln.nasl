##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_url_redirect_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP System Management Homepage (SMH) 'RedirectUrl' URI Redirection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to redirect to his choice
  of malicious site via the trusted vulnerable SMH url or aid in phishing attacks.
  Impact Level: Application.";
tag_affected = "HP System Management Homepage (SMH) version 2.x.";

tag_solution = "No solution or patch is available as of 05th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For details refer, http://welcome.hp.com/country/us/en/welcome.html#Product

  Workaround:
  Apply the work around from below link,
  http://yehg.net/lab/pr0js/advisories/hp_system_management_homepage_url_redirection_abuse";

tag_insight = "Input data passed to the 'RedirectUrl' parameter in 'red2301.html' is not
  being properly validated.";
tag_summary = "This host is running HP System Management Homepage (SMH) and is prone to
  URL redirection vulnerability.";

if(description)
{
  script_id(800759);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1586");
  script_bugtraq_id(39676);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("HP System Management Homepage (SMH) 'RedirectUrl' URI Redirection Vulnerability");
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

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58107");
  script_xref(name : "URL" , value : "https://h20392.www2.hp.com/portal/swdepot/displayProductInfo.do?productNumber=SysMgmtWeb");
  script_xref(name : "URL" , value : "http://yehg.net/lab/pr0js/advisories/hp_system_management_homepage_url_redirection_abuse");

  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_ports("Services/www", 2301);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

smhPort = get_http_port(default:2301);

if(!get_port_state(smhPort)){
  exit(0);
}

## Get HP SMH version from KB
smhVer = get_kb_item("www/" + smhPort+ "/HP/SMH");
if(smhVer)
{
  ## Check HP SMH version <= 2.2.9.1
  if(version_in_range(version:smhVer, test_version:"2.0", test_version2:"2.2.9.3.1")){
    security_warning();
  }
}

##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_unspecified_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP System Management Homepage Unspecified Vulnerability (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to access and
  modify data and cause denial of service conditions.
  Impact Level: Application.";
tag_affected = "HP System Management Homepage (SMH) 6.0 prior to 6.0.0.96";

tag_insight = "The flaw is caused by unspecified errors with unknown impacts and unknown
  attack vectors.";
tag_solution = "Upgarde to HP SMH version 6.0.0.96(for windows)
  http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02029444";
tag_summary = "This host is running  HP System Management Homepage (SMH) and is
  prone to unspecified vulnerability.";

if(description)
{
  script_id(800761);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_bugtraq_id(39632);
  script_cve_id("CVE-2010-1034");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("HP System Management Homepage Unspecified Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Apr/1023909.html");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02029444");

  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_ports("Services/www", 2301);
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
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

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

smhPort = get_http_port(default:2301);
if(!get_port_state(smhPort)){
  exit(0);
}

## Get HP SMH version from KB
smhVer = get_kb_item("www/" + smhPort+ "/HP/SMH");
if(smhVer != NULL)
{
  ## Check HP SMH version < 6.0.0.96
  if(version_in_range(version:smhVer, test_version:"6.0", test_version2:"6.0.0.95")){
    security_warning(smhPort);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_mult_bof_vuln_dec12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# OpenOffice Multiple Buffer Overflow Vulnerabilities - Dec12 (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service condition or execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "OpenOffice version before 3.4.1 on windows";

tag_insight = "- An integer overflow error in the vclmi.dll module when allocating memory
    for an embedded image object.
  - Multiple heap-based buffer overflows in the XML manifest encryption tag
    parsing functionality allows attacker to crash the application via crafted
    Open Document Tex (.odt) file.";
tag_solution = "Upgrade to OpenOffice version 3.4.1 or later,
  For updates refer to http://www.openoffice.org/download/";
tag_summary = "This host is installed with OpenOffice and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803083);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1149", "CVE-2012-2665");
  script_bugtraq_id(53570, 54769);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-24 15:26:59 +0530 (Mon, 24 Dec 2012)");
  script_name("OpenOffice Multiple Buffer Overflow Vulnerabilities - Dec12 (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/81988");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46992/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50438/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027068");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1027332");
  script_xref(name : "URL" , value : "http://www.openoffice.org/security/cves/CVE-2012-2665.html");
  script_xref(name : "URL" , value : "http://www.openoffice.org/security/cves/CVE-2012-1149.html");

  script_description(desc);
  script_summary("Check for the version of OpenOffice on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_require_keys("OpenOffice/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

officeVer = "";

## Get the version from KB
officeVer = get_kb_item("OpenOffice/Win/Ver");
if(!officeVer){
  exit(0);
}

## Check for OpenOffice version less than 3.4.1
## (Display Version comes as 3.41.9593)
if(version_is_less(version: officeVer, test_version:"3.41.9593")){
  security_hole(0);
}

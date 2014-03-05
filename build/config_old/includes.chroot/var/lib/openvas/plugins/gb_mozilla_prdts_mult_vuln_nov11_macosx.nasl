###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_nov11_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mozilla Products Multiple Vulnerabilities (MAC OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_solution = "Upgrade to Mozilla Firefox version 8.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version to 8.0 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service and
  execute arbitrary code via unspecified vectors.
  Impact Level: System/Application";
tag_affected = "Thunderbird version prior to 8.0
  Mozilla Firefox version prior to 8.0";
tag_insight = "The flaws are due to
  - Error in browser engine, which fails to properly handle links from SVG
    mpath elements to non-SVG elements.
  - Error in browser engine, which fails to properly allocate memory.
  - Not properly interacting with the GPU memory behavior of a certain driver
    for Intel integrated GPUs.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802514);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-3654", "CVE-2011-3653", "CVE-2011-3652");
  script_bugtraq_id(50602, 50592, 50600);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-14 12:41:48 +0530 (Mon, 14 Nov 2011)");
  script_name("Mozilla Products Multiple Vulnerabilities (MAC OS X)");
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

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-48.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_require_keys("Mozilla/Firefox/MacOSX/Version",
                  "ThunderBird/MacOSX/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"8.0"))
  {
     security_hole(0);
     exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("ThunderBird/MacOSX/Version");
if(tbVer != NULL)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"8.0")){
    security_hole(0);
  }
}

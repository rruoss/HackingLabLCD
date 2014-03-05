###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln_nov11_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Shockwave Player Multiple Vulnerabilities (MAC OS X)- Nov 2011
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  cause a denial of service.
  Impact Level: Application/System";
tag_affected = "Adobe Shockwave Player Versions prior to 11.6.3.633 on Mac Os X";
tag_insight = "Multiple flaws are due to an error in,
  - DIRAPI.dll and TextXtra.x32 when parsing Director file headers.
  - DIRAPI.dll when parsing rcsl chunks within Director files.";
tag_solution = "Upgrade to Adobe Shockwave Player version 11.6.3.633 or later,
  For updates refer to http://get.adobe.com/shockwave/otherversions/";
tag_summary = "This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802507);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-2446", "CVE-2011-2447", "CVE-2011-2448", "CVE-2011-2449");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-10 13:18:33 +0530 (Thu, 10 Nov 2011)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities (MAC OS X) - Nov 2011");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46667/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-27.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Shockwave Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_require_keys("Adobe/Shockwave/Player/MacOSX/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

shockVer = get_kb_item("Adobe/Shockwave/Player/MacOSX/Version");
if(!shockVer){
  exit(0);
}

## Check for Adobe Shockwave Player versions prior to 11.6.3.633
if(version_is_less(version:shockVer, test_version:"11.6.3.633")){
  security_hole(0);
}

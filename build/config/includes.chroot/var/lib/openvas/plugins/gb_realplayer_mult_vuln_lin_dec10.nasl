###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_vuln_lin_dec10.nasl 14 2013-10-27 12:33:37Z jan $
#
# RealNetworks RealPlayer Multiple Vulnerabilities (Linux)- Dec 10
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
  code or cause a denial of service.";
tag_affected = "RealPlayer Version 11.0.2.1744 on Linux platform.";
tag_insight = "The multiple flaws are due to,
  - An error in the 'Cook' codec initialization function
  - Heap-based buffer overflow when parsing of 'Cook' codec information in a
    Real Audio file with many subbands
  - Memory corruption error in parsing of a 'RV20' video stream
  - Cross-site scripting in ActiveX control and several HTML files
  - Heap-based buffer overflow errors in the cook codec functions
  - Heap-based buffer overflow when parsing 'AAC', 'IVR', 'RealMedia',
    'RA5' and 'SIPR' files
  - Integer overflow in the handling of frame dimensions in a 'SIPR' stream
  - Heap-based buffer overflow error when parsing a large Screen Width value
    in the Screen Descriptor header of a GIF87a file in an RTSP stream
  - An integer overflow in the pnen3260.dll module allows remote attackers to
    execute arbitrary code via a crafted TIT2 atom in an AAC file
  - An use-after-free error allows remote attackers to execute arbitrary code
    or cause a denial of service via a crafted StreamTitle tag in an ICY
    SHOUTcast stream, related to the SMIL file format
  - An integer overflow errror allows remote attackers to execute arbitrary
    code or cause a denial of service via a malformed MLLT atom in an AAC file
  - Heap-based buffer overflow when handling of multi-rate audio streams";
tag_solution = "Upgrade to RealPlayer version 11.0.2.2315 or later,
  For updates refer to http://www.real.com/player";
tag_summary = "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801676);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-29 07:31:27 +0100 (Wed, 29 Dec 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-0121", "CVE-2010-2579", "CVE-2010-2997",
                "CVE-2010-2999", "CVE-2010-4375", "CVE-2010-4376",
                "CVE-2010-4377", "CVE-2010-4378", "CVE-2010-4379",
                "CVE-2010-4382", "CVE-2010-4383", "CVE-2010-4384",
                "CVE-2010-4385", "CVE-2010-4386", "CVE-2010-4387",
                "CVE-2010-4389", "CVE-2010-4390", "CVE-2010-4392",
                "CVE-2010-4395", "CVE-2010-4397");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities (Linux) - Dec 10");
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
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-5/");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/08262010_player/en/");

  script_description(desc);
  script_summary("Check for the version of RealPlayer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_realplayer_detect_lin.nasl");
  script_require_keys("RealPlayer/Linux/Ver");
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

rpVer = get_kb_item("RealPlayer/Linux/Ver");
if(isnull(rpVer)){
  exit(0);
}

## Realplayer version 11.0.2.2315
if(version_is_equal(version:rpVer, test_version:"11.0.2.1744")) {
  security_hole(0);
}

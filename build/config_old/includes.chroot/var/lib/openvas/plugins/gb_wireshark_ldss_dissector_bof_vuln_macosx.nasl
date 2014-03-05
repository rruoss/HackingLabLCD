###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_ldss_dissector_bof_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Wireshark LDSS Dissector Buffer Overflow Vulnerability (Mac OS X)
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
tag_impact = "Successful exploitation will allow attackers to crash the application.
  Impact Level: Application";
tag_affected = "Wireshark version 1.2.0 to 1.2.12 and 1.4.0 to 1.4.1";
tag_insight = "The flaw is due to heap based buffer overflow in
  'dissect_ldss_transfer()' function (epan/dissectors/packet-ldss.c) in the
  LDSS dissector, which allows attackers to cause a denial of service (crash)
  and possibly execute arbitrary code via an LDSS packet with a long digest
  line.";
tag_solution = "Upgrade to Wireshark 1.4.2 or 1.2.13 later.
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802847);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2010-4300");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-04 18:49:10 +0530 (Fri, 04 May 2012)");
  script_name("Wireshark LDSS Dissector Buffer Overflow Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/69354");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42290");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3038");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2010-14.html");

  script_description(desc);
  script_summary("Check for the version of Wireshark on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_require_keys("Wireshark/MacOSX/Version");
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

## Variable Initialization
sharkVer = "";

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

## Check version from 1.4.0 through 1.4.1 or 1.2.0 through 1.2.12
if(version_in_range(version:sharkVer, test_version:"1.4.0", test_version2:"1.4.1") ||
   version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.12")){
  security_hole(0);
}

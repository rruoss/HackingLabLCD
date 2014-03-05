###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_win_jun11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Wireshark Multiple Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Wireshark versions 1.2.x before 1.2.17 and 1.4.x before 1.4.7.";
tag_insight = "- An error in the DICOM dissector can be exploited to cause an infinite loop
    when processing certain malformed packets.
  - An error when processing a Diameter dictionary file can be exploited to
    cause the process to crash.
  - An error when processing a snoop file can be exploited to cause the process
    to crash.
  - An error when processing compressed capture data can be exploited to cause
    the process to crash.
  - An error when processing a Visual Networks file can be exploited to cause
    the process to crash.";
tag_solution = "Upgrade to the Wireshark version 1.2.17 or 1.4.7 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_id(802200);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_bugtraq_id(48066);
  script_cve_id("CVE-2011-1957", "CVE-2011-1958", "CVE-2011-1959", "CVE-2011-2174",
                "CVE-2011-2175");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44449/");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-07.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-08.html");

  script_description(desc);
  script_summary("Check for the version of Wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
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

## Get version from KB
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range (version:sharkVer, test_version:"1.2.0", test_version2:"1.2.16") ||
   version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.6")) {
  security_warning(0);
}

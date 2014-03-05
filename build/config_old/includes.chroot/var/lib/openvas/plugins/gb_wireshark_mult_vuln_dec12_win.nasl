###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_dec12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Wireshark Multiple Dissector Multiple Vulnerabilities - Dec12 (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information, cause denial of service or to consume excessive CPU resources.
  Impact Level: Application";
tag_affected = "Wireshark versions 1.8.x before 1.8.4 on Windows";
tag_insight = "The flaws are due to
  - Hostname disclosure by reading pcap-ng files.
  - The dissect_sflow_245_address_type() in sFlow dissector fails to handle
    length calculations for an invalid IP address type.
  - Errors in 3GPP2 A11, SCTP and EIGRP dissectors, which can be exploited
    to cause a crash.";
tag_solution = "Upgrade to the Wireshark version 1.8.4 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803070);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-6052", "CVE-2012-6054", "CVE-2012-6055", "CVE-2012-6056",
                "CVE-2012-6057");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-10 10:30:54 +0530 (Mon, 10 Dec 2012)");
  script_name("Wireshark Multiple Dissector Multiple Vulnerabilities - Dec12 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51422");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-30.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-32.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-33.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-34.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-39.html");

  script_description(desc);
  script_summary("Check for the version of Wireshark on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
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

## Variable Initialization
sharkVer = "";

## Get version from KB
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.3")) {
  security_warning(0);
}

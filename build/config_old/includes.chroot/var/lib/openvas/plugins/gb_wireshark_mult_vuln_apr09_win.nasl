###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_apr09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Wireshark Multiple Unspecified Vulnerability - Apr09 (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could result in denial of serivce condition.
  Impact Level: Application";
tag_affected = "Wireshark version 0.9.6 to 1.0.6 on Windows";
tag_insight = "- Error exists while processing PN-DCP packet with format string specifiers
    in PROFINET/DCP (PN-DCP) dissector.
  - Error in unknown impact and attack vectors.
  - Error in Lightweight Directory Access Protocol (LDAP) dissector when
    processing unknown attack vectors.
  - Error in Check Point High-Availability Protocol (CPHAP) when processing
    crafted FWHA_MY_STATE packet.
  - An error exists while processing malformed Tektronix .rf5 file.";
tag_solution = "Upgrade to Wireshark 1.0.7
  http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  unspecified vulnerability.";

if(description)
{
  script_id(800396);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-20 14:33:23 +0200 (Mon, 20 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1210", "CVE-2009-1266", "CVE-2009-1267", "CVE-2009-1268",
                "CVE-2009-1269");
  script_bugtraq_id(34291, 34457);
  script_name("Wireshark Multiple Unspecified Vulnerability - Apr09 (Win)");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/8308");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34778");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34542");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Apr/1022027.html");

  script_description(desc);
  script_summary("Check for the version of Wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

# Grep for Wireshark version prior to 1.0.7
if(version_is_less(version:sharkVer, test_version:"1.0.7")){
  security_hole(0);
}

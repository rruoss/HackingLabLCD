###################################################################
# OpenVAS Vulnerability Test
#
# Kaspersky Antivirus UPX Denial of Service vulnerability
#
# LSS-NVT-2010-040
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_solution = "Update to a newer version (automatic update will do).";
tag_summary = "Kaspersky AntiVirus Engine 6.0.1.411 for Windows allows remote
  attackers to cause a denial of service (CPU consumption) via a
  crafted UPX compressed file with a negative offset, which triggers 
  an infinite loop during decompression.";

if(description)
{
  script_id(102051);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2007-1281");
  script_bugtraq_id(22795);
  script_name("Kaspersky Antivirus UPX Denial of Service vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1281");
  script_description(desc);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_summary("Checks for DoS vulnerability in Kaspersky AntiVirus Engine for Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Denial of Service");
  script_dependencies("gb_kaspersky_av_detect.nasl");
  script_require_keys("Kaspersky/AV/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include ("version_func.inc");

version = get_kb_item("Kaspersky/AV/Ver");
if (!version) exit (0);
vuln_version = "6.0.1.411";

is_vuln = version_is_equal (version: version, test_version:vuln_version);

if (is_vuln) {
  security_hole(0);
}

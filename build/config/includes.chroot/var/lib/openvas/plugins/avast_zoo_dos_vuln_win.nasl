###################################################################
# OpenVAS Vulnerability Test
#
# Avast! Zoo Denial of Service Vulnerability
#
# LSS-NVT-2010-039
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
tag_solution = "Update to a newer version.";
tag_summary = "avast! antivirus before 4.7.981 allows remote attackers to
  cause a denial of service (infinite loop) via a Zoo archive
  with a direntry structure that points to a previous file.";

if(description)
{
  script_id(102050);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_cve_id("CVE-2007-1672");
  script_bugtraq_id(23823);
  script_name("Avast! Zoo Denial of Service Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1672");
  script_description(desc);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_summary("Checks for Avast! version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Denial of Service");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_require_keys("Avast!/AV/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include ("version_func.inc");

version = get_kb_item("Avast!/AV/Win/Ver");
if (!version) exit (0);
vuln_version = "4.7.981";

is_vuln = version_is_less_equal (version: version, test_version:vuln_version);

if (is_vuln) {
  security_hole(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_sec_bypass_n_mem_corr_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# ClamAV Security Bypass And Memory Corruption Vulnerabilities (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions.
  Impact Level: System/Application";
tag_affected = "ClamAV version before 0.96 (1.0.26) on Windows.";
tag_insight = "The flaws are due to:
  - An error in handling of 'CAB' and '7z' file formats, which allows to bypass
    virus detection via a crafted archive that is compatible with standard archive
    utilities.
  - An error in 'qtm_decompress' function in 'libclamav/mspack.c', which allows to
    crash application via a crafted CAB archive that uses the Quantum.";
tag_solution = "Upgrade to ClamAV 0.96 or later,
  For updates refer to http://www.clamav.net";
tag_summary = "This host has ClamAV installed, and is prone to security bypass and
  memory corruption vulnerabilities.";

if(description)
{
  script_id(801311);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0098", "CVE-2010-1311");
  script_bugtraq_id(39262);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("ClamAV Security Bypass And Memory Corruption Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39329");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/392749.php");
  script_xref(name : "URL" , value : "http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96");

  script_description(desc);
  script_summary("Check for the Version of ClamAV");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_clamav_detect_win.nasl");
  script_require_keys("ClamAV/Win/Ver");
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

avVer = get_kb_item("ClamAV/Win/Ver");
if(!avVer){
  exit(0);
}
## ClamAv versionless than 0.96 (1.0.26)
if(version_is_less(version:avVer, test_version:"1.0.26")){
  security_hole(0);
}

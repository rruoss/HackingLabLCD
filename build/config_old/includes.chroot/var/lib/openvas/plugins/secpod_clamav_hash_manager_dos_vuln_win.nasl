###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_clamav_hash_manager_dos_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# ClamAV Hash Manager Off-By-One Denial of Service Vulnerability (Win)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to provide a message with
  specially-crafted hash signature in it, leading to denial of service
  (clamscan executable crash).
  Impact Level: Application";
tag_affected = "ClamAV version prior to 0.97.2 (3.0.3.6870) on Windows.";
tag_insight = "The flaw is due to the way the hash manager of Clam AntiVirus
  scans messages with certain hashes.";
tag_solution = "Upgrade to ClamAV 0.97.2 or later,
  For updates refer to http://www.clamav.net/lang/en/";
tag_summary = "This host has ClamAV installed and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(902726);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-2721");
  script_bugtraq_id(48891);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("ClamAV Hash Manager Off-By-One Denial of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45382");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68785");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/07/26/3");

  script_description(desc);
  script_summary("Check for the Version of ClamAV");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Denial of Service");
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

## ClamAv version less than 0.97.2 (3.0.3.6870)
if(version_is_less(version:avVer, test_version:"3.0.3.6870")){
  security_warning(0);
}

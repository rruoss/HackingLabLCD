###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_file_reporter_files_del_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Novell File Reporter 'SRS' Tag Arbitrary File Deletion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to delete arbitrary
  files.
  Impact Level: Application";
tag_affected = "Novell File Reporter (NFR) before 1.0.4.2";
tag_insight = "The flaw is due to an error in the NFR Agent (NFRAgent.exe) when
  handling 'OPERATION'  and 'CMD' commands in the 'SRS' tag and can be
  exploited to delete arbitrary files via a specially crafted SRS request
  sent to TCP port 3073.";
tag_solution = "No solution or patch is available as of 22nd January, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://download.novell.com/Download?buildid=rCAgCcbPH9s~";
tag_summary = "This host is installed with Novell File Reporter and is prone to
  arbitrary file deletion vulnerability.";

if(description)
{
  script_id(801960);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2750");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Novell File Reporter 'SRS' Tag Arbitrary File Deletion Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45071");
  script_xref(name : "URL" , value : "http://aluigi.org/adv/nfr_2-adv.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/518632/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Novell File Reporter");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_keys("Novell/FileReporter/Ver");
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
nfrVer = get_kb_item("Novell/FileReporter/Ver");
if(nfrVer)
{
  ## Check for  Novell File Reporter version less than or equal 1.0.4.2
  if(version_is_less_equal(version:nfrVer, test_version:"1.0.400.2")){
    security_warning(0);
  }
}

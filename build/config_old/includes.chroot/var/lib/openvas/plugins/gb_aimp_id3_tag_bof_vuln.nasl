###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aimp_id3_tag_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# AIMP ID3 Tag Buffer Overflow Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated to CVE-2009-3170
# - By Nikita MR <rnikita@secpod.com> On 2009-09-15 #4729
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
tag_impact = "Successful exploitation will allow remote attackers to exploit arbitrary
  code in the context of the affected application.

  Impact level: Application";

tag_affected = "AIMP2 version 2.5.1.330 and prior.";
tag_insight = "- A boundary check error exists while processing MP3 files with overly long
    ID3 tag.
  - Stack-based buffer overflow occurs when application fails to handle long
    File1 argument in a '.pls' or '.m3u' playlist file.";
tag_solution = "No solution or patch is available as of 15th September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.aimp.ru/index.php?newlang=english";
tag_summary = "This host has AIMP2 player installed and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_id(800591);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1944", "CVE-2009-3170");
  script_name("AIMP ID3 Tag Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35295/");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9561");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8837");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50875");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2530");

  script_description(desc);
  script_summary("Check for the version of AIMP2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_aimp_detect.nasl");
  script_require_keys("AIMP/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

aimpVer = get_kb_item("AIMP/Ver");

if(aimpVer != NULL)
{
  # Grep for AIMP2 Player 2.5.1.330 and prior
  if(version_is_less_equal(version:aimpVer, test_version:"2.5.1.330")){
    security_hole(0);
  }
}

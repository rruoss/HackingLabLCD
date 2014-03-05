###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_file_reporter_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Novell File Reporter 'NFRAgent.exe' XML Parsing Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges or cause denial of service.
  Impact Level: Application/System";
tag_affected = "Novell File Reporter (NFR) before 1.0.2";
tag_insight = "The flaw exists within 'NFRAgent.exe' module, which allows remote attackers
  to execute arbitrary code via unspecified XML data to port 3037.";
tag_solution = "Upgrade Novell File Reporter 1.0.2 or later,
  For updates refer to http://download.novell.com/Download?buildid=rCAgCcbPH9s~";
tag_summary = "This host is installed with Novell File Reporter and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(801918);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-13 15:50:09 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2011-0994");
  script_bugtraq_id(47144);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Novell File Reporter 'NFRAgent.exe' XML Parsing Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-116/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/517321/100/0/threaded");

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
  ## Check for  Novell File Reporter version less than 1.0.2
  ## Novell File Reporter(1.0.1) 1.0.117
  if(version_is_less_equal(version:nfrVer, test_version:"1.0.117")){
    security_hole(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_iprint_client_printer_url_mult_bof_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Novell iPrint Client 'printer-url' Multiple BOF Vulnerabilities (Windows)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code under
  the context of the browser.
  Impact Level: Application";
tag_affected = "Novell iPrint Client version prior to 5.64 on windows.";
tag_insight = "The flaws exists within the 'nipplib' component which is used by both the
  ActiveX and Netscape compatible browser plugins. When handling the various
  parameters from the user specified printer-url the process blindly copies
  user supplied data into a fixed-length buffer on the heap.";
tag_solution = "Upgrade to Novell iPrint Client 5.64 or later,
  For the updates refer, http://download.novell.com/Download?buildid=6_bNby38ERg~";
tag_summary = "The host is installed with Novell iPrint Client and is prone to
  multiple buffer overflow vulnerabilities.";

if(description)
{
  script_id(801951);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1699", "CVE-2011-1700", "CVE-2011-1701", "CVE-2011-1702",
                "CVE-2011-1703", "CVE-2011-1704", "CVE-2011-1705", "CVE-2011-1706",
                "CVE-2011-1707", "CVE-2011-1708");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Novell iPrint Client 'printer-url' Multiple BOF Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1025606");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-172/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-173/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-174/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-175/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-176/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-177/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-178/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-179/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-180/");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-11-181/");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Novell iPrint Client");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_keys("Novell/iPrint/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");

## Get the version from KB
iPrintVer = get_kb_item("Novell/iPrint/Ver");
if(!iPrintVer){
  exit(0);
}

## Check for Novell iPrint Client Version < 5.64
if(version_is_less(version:iPrintVer, test_version:"5.64")){
 security_hole(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ghostscript_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Ghostscript 'iscan.c' PDF Handling Remote Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation allows the attackers to execute arbitrary code or
  cause a denial of service (memory corruption) via a crafted PDF document
  containing a long name.
  Impact Level: Application";
tag_affected = "Ghostscript version 8.64 and prior";
tag_insight = "The flaw is due to improper bounds checking by 'iscan.c' when
  processing malicious 'PDF' files, which leads to open a specially-crafted
  PDF file.";
tag_solution = "Upgrade to Ghostscript version 8.71 or later,
  For updates refer to http://www.ghostscript.com/";
tag_summary = "This host is installed with Ghostscript and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(801411);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41593);
  script_cve_id("CVE-2009-4897");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Ghostscript 'iscan.c' PDF Handling Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40580");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60380");

  script_description(desc);
  script_summary("Check for the Version of Ghostscript");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_ghostscript_detect_win.nasl");
  script_require_keys("Ghostscript/Win/Ver");
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

## Get the version from KB
ghostVer = get_kb_item("Ghostscript/Win/Ver");
if(!ghostVer){
  exit(0);
}

## Check for the Ghostscript version <= 8.64
if(version_is_less_equal(version:ghostVer, test_version:"8.64")){
   security_hole(0);
}

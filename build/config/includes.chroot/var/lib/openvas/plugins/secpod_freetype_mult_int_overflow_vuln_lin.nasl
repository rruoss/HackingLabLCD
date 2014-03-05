###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_freetype_mult_int_overflow_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# FreeType Multiple Integer Overflow Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_solution = "Apply fix from the below repositories,
  http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=0545ec1ca36b27cb928128870a83e5f668980bc5
  http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=79972af4f0485a11dcb19551356c45245749fc5b
  http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=a18788b14db60ae3673f932249cd02d33a227c4e

  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application.
  Impact Level: System/Application.";
tag_affected = "FreeType version 2.3.9 and prior on Linux.";
tag_insight = "Multiple integer overflows are due to inadequate validation of data passed
  into cff/cffload.c, sfnt/ttcmap.c and cff/cffload.c while processing
  specially crafted fonts.";
tag_summary = "This host has FreeType installed and is prone to Multiple Integer Overflow
  vulnerability.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.900631";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-24 16:23:28 +0200 (Fri, 24 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0946");
  script_name("FreeType Multiple Integer Overflow Vulnerability (Linux)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/34723");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=491384");

  script_description(desc);
  script_summary("Check for the version of FreeType");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_freetype_detect_lin.nasl");
  script_require_keys("FreeType/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

ver = get_app_version(cpe:"cpe:/a:freetype:freetype", nvt:SCRIPT_OID);
if(version_is_less_equal(version:ver, test_version:"2.3.9")){
  security_hole(0);
}

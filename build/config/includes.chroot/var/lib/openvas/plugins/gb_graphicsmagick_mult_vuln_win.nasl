###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_graphicsmagick_mult_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# GraphicsMagick Multiple Vulnerabilities (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "A remote user could execute arbitrary code on the target system and can
  cause denial-of-service or compromise a vulnerable system via specially
  crafted PALM, PICT, XCF, DPX, and CINEON images.

  Impact level: System/Application";

tag_affected = "GraphicsMagick version prior to 1.1.14 and 1.2.3 on Windows.";
tag_insight = "Multiple flaws due to,
  - two boundary errors within the ReadPALMImage function in coders/palm.c,
  - a boundary error within the DecodeImage function in coders/pict.a,
  - unknown errors within the processing of XCF, DPX, and CINEON images.
  - error exists while processing malformed data in DPX which causes input
    validation vulnerability.";
tag_solution = "Update to version 1.1.14 or 1.2.3,
  http://sourceforge.net/projects/graphicsmagick";
tag_summary = "This host is running GraphicsMagick graphics tool and is prone
  to multiple buffer overflow/underflow vulnerabilities.";

if(description)
{
  script_id(800515);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-18 15:32:11 +0100 (Wed, 18 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-6070", "CVE-2008-6071", "CVE-2008-6072", "CVE-2008-6621");
  script_bugtraq_id(29583);
  script_name("GraphicsMagick Multiple Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30549");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/1767");
  script_xref(name : "URL" , value : "http://sourceforge.net/project/shownotes.php?release_id=604837");
  script_xref(name : "URL" , value : "http://cvs.graphicsmagick.org/cgi-bin/cvsweb.cgi/GraphicsMagick/coders/dpx.c");
  script_xref(name : "URL" , value : "http://cvs.graphicsmagick.org/cgi-bin/cvsweb.cgi/GraphicsMagick/coders/xcf.c");
  script_xref(name : "URL" , value : "http://cvs.graphicsmagick.org/cgi-bin/cvsweb.cgi/GraphicsMagick/coders/pict.c");
  script_xref(name : "URL" , value : "http://cvs.graphicsmagick.org/cgi-bin/cvsweb.cgi/GraphicsMagick/coders/cineon.c");

  script_description(desc);
  script_summary("Check for the version of GraphicsMagick");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_graphicsmagick_detect_win.nasl");
  script_require_keys("GraphicsMagick/Win/Ver");
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

gmVer = get_kb_item("GraphicsMagick/Win/Ver");
if(gmVer == NULL){
  exit(0);
}

# Check for version 1.0 to 1.1.13 and 1.2 to 1.2.2
if(version_in_range(version:gmVer, test_version:"1.0", test_version2:"1.1.13") ||
   version_in_range(version:gmVer, test_version:"1.2", test_version2:"1.2.2")){
  security_hole(0);
}

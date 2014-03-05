###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xemacs_mult_bof_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# XEmacs Multiple Buffer Overflow Vulnerabilities (Win)
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
tag_impact = "Attackers can exploit this issue to execute arbitrary code in the context of
  affected application, and can cause denial of service.
  Impact Level: Application";
tag_affected = "XEmacs version 21.4.22 and prior on Windows.";
tag_insight = "Error exists when 'tiff_instantiate' function processing a crafted TIFF file,
  'png_instantiate' function processing a crafted PNG file, 'jpeg_instantiate'
  function processing a crafted JPEG file in the glyphs-eimage.c script that
  can be exploited to cause a heap-based buffer overflow.";
tag_solution = "No solution or patch is available as of 07th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://xemacs.org/";
tag_summary = "The host is installed with XEmacs and is prone to multiple
  Buffer Overflow vulnerabilities.";

if(description)
{
  script_id(800927);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2688");
  script_bugtraq_id(35473);
  script_name("XEmacs Multiple Buffer Overflow Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35348");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1666");

  script_description(desc);
  script_summary("Check for the Version of XEmacs");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_xemacs_detect_win.nasl");
  script_require_keys("XEmacs/Win/Ver");
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

xemacsVer = get_kb_item("XEmacs/Win/Ver");

if(xemacsVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:xemacsVer, test_version:"21.4.22")){
  security_hole(0);
}

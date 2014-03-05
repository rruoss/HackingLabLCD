###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_imagemagick_bof_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# ImageMagick Buffer Overflow Vulnerability (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Attackers can exploit this issue by executing arbitrary code via a crafted
  TIFF files in the context of an affected application.
  Impact Level: Application";
tag_affected = "ImageMagick version prior to 6.5.2-9 on Windows.";
tag_insight = "The flaw occurs due to an integer overflow error within the 'XMakeImage()'
  function in magick/xwindow.c file while processing malformed TIFF files.";
tag_solution = "Upgrade to ImageMagick version 6.5.2-9 or later.
  http://www.imagemagick.org/script/download.php";
tag_summary = "The host is installed with ImageMagick and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_id(900564);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-02 08:16:42 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1882");
 script_bugtraq_id(35111);
  script_name("ImageMagick Buffer Overflow Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35216/");

  script_description(desc);
  script_summary("Check for the Version of ImageMagick");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_require_keys("ImageMagick/Win/Ver");
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

imageVer = get_kb_item("ImageMagick/Win/Ver");
if(!imageVer){
  exit(0);
}

if(version_is_less(version:imageVer, test_version:"6.5.2.9")){
  security_hole(0);
}

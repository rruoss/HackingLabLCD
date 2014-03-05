###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: gb_xnview_decompressing_heap_overflow_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# XnView Multiple Image Decompression Heap Overflow Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "This host has XnView installed and is prone to multiple heap
  based buffer overflow vulnerabilities.

  Vulnerabilities Insight:
  - Insufficient validation when decompressing SGI32LogLum compressed
    TIFF images.
  - Insufficient validation when decompressing SGI32LogLum compressed TIFF
    images where the PhotometricInterpretation encoding is set to LogL.
  - Insufficient validation when decompressing PCT images.
  - An indexing error when processing the ImageDescriptor structure of GIF
    images.";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code on the
  system or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "XnView versions prior to 1.99 on windows";
tag_solution = "Update to XnView version 1.99 or later,
  For updates refer to http://www.xnview.com/";

if(description)
{
  script_id(802444);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0276", "CVE-2012-0277", "CVE-2012-0282");
  script_bugtraq_id(54125);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-24 15:21:56 +0530 (Tue, 24 Jul 2012)");
  script_name("XnView Multiple Image Decompression Heap Overflow Vulnerabilities (Windows)");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


  script_description(desc);
  script_summary("Check for the version of XnView");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_require_keys("XnView/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48666");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19336/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19337/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19338/");
  script_xref(name : "URL" , value : "http://newsgroup.xnview.com/viewtopic.php?f=35&amp;t=25858");
  script_xref(name : "URL" , value : "http://www.protekresearchlab.com/index.php?option=com_content&amp;view=article&amp;id=48");
  script_xref(name : "URL" , value : "http://www.protekresearchlab.com/index.php?option=com_content&amp;view=article&amp;id=49");
  script_xref(name : "URL" , value : "http://www.protekresearchlab.com/index.php?option=com_content&amp;view=article&amp;id=50");
  exit(0);
}


include("version_func.inc");

# Variable Initialization
xnviewVer = NULL;

## Get XnView from KB
xnviewVer = get_kb_item("XnView/Win/Ver");
if(isnull(xnviewVer)){
  exit(0);
}

## Check if the version is < 1.99
if(version_is_less(version:xnviewVer, test_version:"1.99")){
  security_hole(0);
}

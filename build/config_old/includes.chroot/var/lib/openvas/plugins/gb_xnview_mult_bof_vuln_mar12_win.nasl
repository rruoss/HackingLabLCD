###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: gb_xnview_mult_bof_vuln_mar12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# XnView Multiple Buffer Overflow Vulnerabilities - Mar12 (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_summary = "This host has XnView installed and is prone to multiple heap based
  buffer overflow vulnerabilities.

  Vulnerabilities Insight:
  The flaws are due to
  - A signedness error in the FlashPix plugin (Xfpx.dll) when validating
    buffer sizes to process image's content.
  - An error when processing image data within Personal Computer eXchange
    (PCX) files.
  - A boundary error when parsing a directory, which allows attackers to cause a
    buffer overflow when browsing folder from an extracted archive file.";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code on the
  system via a specially crafted files or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "XnView versions 1.98.5 and prior on windows";
tag_solution = "Update to XnView version 1.98.8 or later,
  For updates refer to http://www.xnview.com/";

if(description)
{
  script_id(802815);
  script_version("$Revision: 12 $");
  script_bugtraq_id(52405);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-15 12:56:44 +0530 (Thu, 15 Mar 2012)");
  script_name("XnView Multiple Buffer Overflow Vulnerabilities - Mar12 (Win)");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47388/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18491/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52405/info");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7726-6132_102-5285780.html");

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

## Check if the version is < 1.98.8
if(version_is_less(version:xnviewVer, test_version:"1.98.8")){
  security_hole(0);
}

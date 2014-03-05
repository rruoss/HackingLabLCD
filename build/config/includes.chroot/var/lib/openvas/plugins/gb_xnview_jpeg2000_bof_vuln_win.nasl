###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: gb_xnview_jpeg2000_bof_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# XnView JPEG2000 Plugin Buffer Overflow Vulnerability (Win)
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
tag_summary = "This host has XnView installed and is prone to buffer overflow
  vulnerability.

  Vulnerabilities Insight:
  The flaw is due to an error in the JPEG2000 plugin in Xjp2.dll, when
  processing a JPEG2000 (JP2) file with a crafted Quantization Default (QCD)
  marker segment.";

tag_impact = "Successful exploitation will allows attackers to execute arbitrary code in
  the context of the affected application or cause a denial of service
  condition.
  Impact Level: System/Application";
tag_affected = "XnView version 1.98.5 and prior.";
tag_solution = "No solution or patch is available as of 15th March, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.xnview.com/";

if(description)
{
  script_id(802816);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1051");
  script_bugtraq_id(51896);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-15 16:28:54 +0530 (Thu, 15 Mar 2012)");
  script_name("XnView JPEG2000 Plugin Buffer Overflow Vulnerability (Win)");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://osvdb.org/78904");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47352");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73040");

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

## Check if the version is equal to 1.98.5
if(version_is_less_equal(version:xnviewVer, test_version:"1.98.5")){
  security_hole(0);
}

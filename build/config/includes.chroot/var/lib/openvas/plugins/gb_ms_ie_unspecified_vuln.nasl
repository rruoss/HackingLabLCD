###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_unspecified_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Internet Explorer Unspecified vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Impact is currently unknown.
  Impact Level: Application";
tag_affected = "Microsoft Internet Explorer 7.0 Windows XP SP3 and prior.
  Microsoft Internet Explorer 7.0 Windows Server 2K3 SP2 and prior.";
tag_insight = "The flaw exists due to the error in processing of 'XML' document that references
  a crafted web site via the 'SRC' attribute of an image element.";
tag_solution = "No solution or patch is available as of 01st April, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host is installed with Microsoft Internet Explorer and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(800742);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-1175");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Internet Explorer Unspecified vulnerability");
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
  script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-1175");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/510280/100/0/threaded");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Microsoft Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
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
include("secpod_reg.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(ieVer)
{
  # Check for IE Version 7.x
  if(ieVer =~ "^7\."){
    security_hole(0);
  }
}

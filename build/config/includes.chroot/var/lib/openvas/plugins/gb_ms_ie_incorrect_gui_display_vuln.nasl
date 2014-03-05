###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_incorrect_gui_display_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Internet Explorer Incorrect GUI Display Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Antu sanadi <santu@secpod.com> on 2011-05-18
#  - This plugin is invalidated by secpod_ms11-006.nasl
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
tag_impact = "Successful exploits will allow an attacker to trigger an incorrect GUI
  display and have unspecified other impact.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer on Windows XP";
tag_insight = "The flaw is caused due an error which allows remote attackers to trigger an
  incorrect GUI display and have unspecified other impact via vectors related
  to the DOM implementation.";
tag_solution = "No solution or patch is available as of 28th January, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host has installed with Internet Explorer and is prone to
  incorrect GUI display vulnerability.";

if(description)
{
  script_id(801831);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0347");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Internet Explorer Incorrect GUI Display Vulnerability");
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
  script_xref(name : "URL" , value : "http://lcamtuf.coredump.cx/cross_fuzz/msie_display.jpg");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2490606.mspx");
  script_xref(name : "URL" , value : "http://lcamtuf.blogspot.com/2011/01/announcing-crossfuzz-potential-0-day-in.html");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


## This plugin is invalidated by secpod_ms11-006.nasl
exit(0);

include("secpod_reg.inc");
include("version_func.inc");

## Check for Win XP
if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

## Get IE version from KB
ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_less_equal(version:ieVer, test_version:"8.0.6001.18702")){
  security_hole(0);
}

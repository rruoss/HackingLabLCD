##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_flashfxp_mult_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# FlashFXP Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation allows an attackers to overflow a buffer and execute
  arbitrary code on the system or cause the application to crash.
  Impact Level: System/Application";
tag_affected = "FlashFXP verison 4.1.8.1701";
tag_insight = "The flaw is due to improper bounds checking by the TListbox or
  TComboBox.";
tag_solution = "Upgrade to FlashFXP verison 4.2 or later
  For updates refer to http://www.flashfxp.com/download";
tag_summary = "This host is installed with FlashFXP and is prone to multiple
  buffer overflow vulnerabilities.";

if(description)
{
  script_id(802965);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4992");
  script_bugtraq_id(52259);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-24 14:23:56 +0530 (Mon, 24 Sep 2012)");
  script_name("FlashFXP Multiple Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/79767");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73626");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18555/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Mar/7");
  script_xref(name : "URL" , value : "http://www.flashfxp.com/forum/flashfxp/news/15473-flashfxp-4-2-released.html#post81101");

  script_description(desc);
  script_summary("Check for the version of FlashFXP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_flashfxp_detect.nasl");
  script_require_keys("FlashFXP/Ver");
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

## Variable Initialization
flashVer = "";

## Get FlashFXP version
flashVer = get_kb_item("FlashFXP/Ver");

## Check for FlashFXP version
if(version_is_equal(version:flashVer, test_version:"4.1.8.1701")){
  security_hole(0);
}

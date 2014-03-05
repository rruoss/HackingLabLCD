###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_bof_vuln_jun09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apple iTunes 'itms:' URI Stack Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful attacks will lead to buffer overflow or denial of service to
  legitimate users.
  Impact Level: Application";
tag_affected = "Apple iTunes version prior to 8.2 on Windows.";
tag_insight = "Error occurs when application fails to perform adequate boundary checks
  before copying user-supplied data to an insufficiently-sized buffer while
  processing a specially crafted 'itms:' URL.";
tag_solution = "Upgrade to Apple iTunes Version 8.2
  http://www.apple.com/itunes/download";
tag_summary = "This host has Apple iTunes installed, which is prone to stack
  based Buffer Overflow vulnerability.";

if(description)
{
  script_id(800804);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0950");
  script_bugtraq_id(35157);
  script_name("Apple iTunes 'itms:' URI Stack Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT3592");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/alerts/2009/Jun/1022313.html");

  script_description(desc);
  script_summary("Check for the version of Apple iTunes");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_require_keys("iTunes/Win/Ver");
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

itunesVer = get_kb_item("iTunes/Win/Ver");
if(!itunesVer){
  exit(0);
}

# Check for iTunes version prior to 8.2 => 8.2.0.23
if(version_is_less(version:itunesVer, test_version:"8.2.0.23")){
  security_hole(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_bof_vuln_jan10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Shockwave Player 3D Model Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful attack could allow attackers to execute arbitrary code and compromise
  a vulnerable system.
  Impact Level: System/Application";
tag_affected = "Adobe Shockwave Player prior to 11.5.6.606 on Windows.";
tag_insight = "These flaws are caused by buffer and integer overflow errors when processing
  Shockwave files or 3D models, which could be exploited to execute arbitrary
  code by tricking a user into visiting a specially crafted web page.";
tag_solution = "Upgrade to Adobe Shockwave Player 11.5.6.606 or later.
  For updates refer to http://get.adobe.com/shockwave/otherversions/";
tag_summary = "This host has Adobe Shockwave Player installed and is prone to
  Buffer Overflow vulnerabilities.";

if(description)
{
  script_id(800443);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-4003", "CVE-2009-4002");
  script_bugtraq_id(37872, 37870);
  script_name("Adobe Shockwave Player 3D Model Buffer Overflow Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2009-61/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0171");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jan/1023481.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-03.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/509062/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Adobe Shockwave Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_require_keys("Adobe/ShockwavePlayer/Ver");
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

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer){
  exit(0);
}

# Grep for version prior to 11.5.6.606
if(version_is_less(version:shockVer, test_version:"11.5.6.606")){
  security_hole(0);
}

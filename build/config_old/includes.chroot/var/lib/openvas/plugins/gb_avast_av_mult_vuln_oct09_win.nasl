###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_av_mult_vuln_oct09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# avast! Multiple Vulnerabilities - Oct09 (Win)
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
tag_impact = "Successful exploitation will let the local attackers to cause a Denial of
  Service or gain escalated privileges on the victim's system.
  Impact Level: System/Application";
tag_affected = "avast! Home and Professional version prior to 4.8.1356 on Windows";
tag_insight = "- A boundary error exists in the 'aswMon2' kernel driver when processing
    IOCTLs. This can be exploited to cause a stack-based buffer overflow
    via a specially crafted 0xB2C80018 IOCTL.
  - An error in the 'AavmKer4.sys' kernel driver that can be exploited to
    corrupt memory via a specially crafted 0xB2D6000C or 0xB2D60034 IOCTL.
  - An unspecified error exists in the ashWsFtr.dll library which can be
    exploited to cause unknow impact.";
tag_solution = "Upgrade to avast! version 4.8.1356 or later
  http://www.avast.com/eng/download.html";
tag_summary = "This host is installed with avast! AntiVirus and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801111);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3522", "CVE-2009-3523", "CVE-2009-3524");
  script_bugtraq_id(36507);
  script_name("avast! Multiple Vulnerabilities - Oct09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36858/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/506681");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2761");

  script_description(desc);
  script_summary("Check  the version of avas ! Antivirus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_avast_av_detect_win.nasl");
  script_require_keys("Avast!/AV/Win/Ver");
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

avastVer = get_kb_item("Avast!/AV/Win/Ver");
if(isnull(avastVer)){
  exit(0);
}

# Check for avast! versions prior to 4.8.1356
if(version_is_less(version:avastVer, test_version:"4.8.1356")){
  security_hole(0);
}

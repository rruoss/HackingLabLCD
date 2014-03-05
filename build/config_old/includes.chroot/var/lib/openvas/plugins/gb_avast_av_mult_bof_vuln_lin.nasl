###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avast_av_mult_bof_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# avast! AntiVirus Multiple BOF Vulnerabilities (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Attackers can exploit this issue to execute arbitrary code in the context
  of affected application, and can cause denial of service.
  Impact Level: Application";
tag_affected = "avast! Linux Home Edition 1.0.8-2 and prior on Linux";
tag_insight = "Multiple buffer overflow errors occur while processing malformed ISO or
  RPM files as the application fails to perform adequate bounds check on
  files before copying them into an insufficiently sized buffer.";
tag_solution = "Upgrade to avast! Linux Home Edition latest version
  http://www.avast.com/index.html";
tag_summary = "The host is installed with avast! AntiVirus and is prone to
  multiple Buffer Overflow Vulnerabilities.";

if(description)
{
  script_id(800599);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-6846");
  script_bugtraq_id(32747);
  script_name("avast! AntiVirus Multiple BOF Vulnerabilities (Linux)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/47251");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/382096.php");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/3460");

  script_description(desc);
  script_summary("Check for the Version of avast! Linux Home Edition");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_avast_av_detect_lin.nasl");
  script_require_keys("Avast!/AV/Linux/Ver");
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

avastVer = get_kb_item("Avast!/AV/Linux/Ver");
if(avastVer == NULL){
  exit(0);
}

# Check for avast! Linux Home Edition version <= 1.0.8-2 (1.0.8)
if(version_is_less_equal(version:avastVer, test_version:"1.0.8")){
  security_hole(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_f-prot_av_sec_bypass_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# F-PROT AntiVirus Security Bypass Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Attackers can exploit this issue to bypass the malware detection and
  to execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "F-PROT AV version 6.0.2 and prior on Linux.";
tag_insight = "The flaw is due to an error in the file parsing engine while
  processing specially crafted CAB files.";
tag_solution = "Upgrade to F-PROT AV version 6.0.3 or later
  For updates refer to http://www.f-prot.com/";
tag_summary = "The host is installed with F-PROT AntiVirus and is prone to
  Security Bypass vulnerability.";

if(description)
{
  script_id(900555);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1783");
  script_bugtraq_id(34896);
  script_name("F-PROT AntiVirus Security Bypass Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50427");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/advisory-f-prot-frisk-cab-bypass.html");

  script_description(desc);
  script_summary("Check for the Version of F-PROT AV");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_f-prot_av_detect_lin.nasl");
  script_require_keys("F-Prot/AV/Linux/Ver");
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

avVer = get_kb_item("F-Prot/AV/Linux/Ver");
if(!avVer){
  exit(0);
}

# grep for version 6.0.2 => 6.2.1.4252
if(version_is_less_equal(version:avVer, test_version:"6.2.1.4252")){
  security_hole(0);
}

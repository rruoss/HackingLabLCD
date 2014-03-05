###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_mult_vuln_apr09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# ClamAV Multiple Vulnerabilities (Linux)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Remote attackers may exploit this issue to inject malicious files into the
  system which can bypass the scan engine and may cause denial of service.
  Impact Level: System/Application";
tag_affected = "ClamAV before 0.95 on Linux";
tag_insight = "Multiple flaws are due to
  - Error in handling specially crafted RAR files which prevents the scanning
    of potentially malicious files.
  - Inadequate sanitation of files through a crafted TAR file causes clamd and
    clamscan to hang.
  - 'libclamav/pe.c' allows remote attackers to cause a denial of service
    via a crafted EXE which triggers a divide-by-zero error.";
tag_solution = "Upgrade to ClamAV 0.95
  http://www.clamav.net";
tag_summary = "This host has ClamAV installed and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(800554);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1241", "CVE-2009-1270", "CVE-2008-6680");
  script_bugtraq_id(34344, 34357);
  script_name("ClamAV Multiple Vulnerabilities (Linux)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0934");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/04/07/6");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2009/04/clamav-094-and-below-evasion-and-bypass.html");

  script_description(desc);
  script_summary("Check for the Version of ClamAV");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_detect_lin.nasl");
  script_require_keys("ClamAV/Lin/Ver");
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

avVer = get_kb_item("ClamAV/Lin/Ver");
if(avVer == NULL){
  exit(0);
}

if(version_is_less(version:avVer, test_version:"0.95")){
  security_hole(0);
}

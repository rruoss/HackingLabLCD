###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_lzh_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# ClamAV LZH File Unpacking Denial of Service Vulnerability (Linux)
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
tag_affected = "ClamAV 0.93.3 and prior on Linux.";
tag_insight = "A segmentation fault ocurs in the unpack feature,while processing malicious
  LZH file.";
tag_solution = "Upgrade to ClamAV 0.94 or later
  http://www.clamav.net/download";
tag_summary = "The host is installed with ClamAV and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_id(800597);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6845");
  script_bugtraq_id(32752);
  script_name("ClamAV LZH File Unpacking Denial of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/51963");
  script_xref(name : "URL" , value : "http://www.ivizsecurity.com/security-advisory-iviz-sr-08011.html");

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

clamavVer = get_kb_item("ClamAV/Lin/Ver");
if(clamavVer == NULL){
  exit(0);
}

if(version_is_less_equal(version:clamavVer, test_version:"0.93.3")){
  security_warning(0);
}

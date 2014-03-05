###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cuteftp_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# CuteFTP Heap Based Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  and potentially compromise a user's system.
  Impact Level: System/Application";
tag_affected = "CuteFTP Home/Pro/Lite 8.3.3, 8.3.3.54 on Windows.";
tag_insight = "The flaw is due to error in 'Create New Site' feature when connecting
  to sites having an overly long label. This can be exploited to corrupt heap
  memory by tricking a user into importing a malicious site list and connecting
  to a site having an overly long label.";
tag_solution = "No solution or patch is available as of 15th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cuteftp.com/downloads/";
tag_summary = "The host is installed with CuteFTP and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(800948);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3483");
  script_name("CuteFTP Heap Based Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36874");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53487");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0909-exploits/Dr_IDE-CuteFTP_FTP_8.3.3-PoC.py.txt");

  script_description(desc);
  script_summary("Check for the version of CuteFTP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_cuteftp_detect.nasl");
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

cVer = make_list();

chVer = get_kb_item("CuteFTP/Home/Ver");
if(!isnull(chVer)){
  cVer = make_list(cVer, chVer);
}

clVer = get_kb_item("CuteFTP/Lite/Ver");
if(!isnull(clVer)){
  cVer = make_list(cVer,clVer);
}

cpVer = get_kb_item("CuteFTP/Professional/Ver");
if(!isnull(cpVer)){
  cVer = make_list(cVer,cpVer);
}

foreach ver (cVer)
{
  if(version_is_equal(version:ver, test_version:"8.3.3") ||
     version_is_equal(version:ver, test_version:"8.3.3.54"))
  {
    security_hole(0);
    exit(0);
  }
}

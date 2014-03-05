###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_formmax_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# FormMax Buffer Overflow Vulnerability
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
tag_impact = "Attackers can exploit this issue by executing arbitrary code in the context
  of an affected application.
  Impact Level: Application";
tag_affected = "FormMax version 3.5 and prior";
tag_insight = "The flaw is due to boundary error while processing malicious '.aim'
  import files leading to heap-based buffer overflow.";
tag_solution = "No solution or patch is available as of 30th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cutepdf.com/products/FormMax/";
tag_summary = "The host is installed with FormMax and is prone to Buffer
  Overflow Vulnerability.";

if(description)
{
  script_id(900972);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3790");
  script_name("FormMax Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/59079");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36943");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53890");

  script_description(desc);
  script_summary("Check for the version of FormMax");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_formmax_detect.nasl");
  script_require_keys("FormMax/Evaluation/Ver");
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

fmVer = get_kb_item("FormMax/Evaluation/Ver");
if(!fmVer){
  exit(0);
}

if(version_is_less_equal(version:fmVer, test_version:"3.5")){
  security_hole(0);
}

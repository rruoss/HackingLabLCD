###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openoffice_mult_code_exec_vuln_win_feb10.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenOffice Multiple Remote Code Execution Vulnerabilities - Feb10
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation lets the attackers to cause a denial of service
  or execute arbitrary code.
  Impact Level: Application/System";
tag_affected = "OpenOffice.org versions prior to 3.2";
tag_insight = "- GIF Files in GIFLZWDecompressor:: GIFLZWDecompressor function in
    filter.vcl/lgif/decode.cxx leading to heap overflow.
  - XPM files in XPMReader::ReadXPM function in filter.vcl/ixpm/svt_xpmread.cxx
    leading to an integer overflow.
  - Microsoft Word document in filter/ww8/ww8par2.cxx leading to application
    crash or execute arbitrary code via crafted sprmTSetBrc table property
    in a Word document.";
tag_solution = "Upgrade to OpenOffice.org version 3.2 or later,
  http://download.openoffice.org/index.html";
tag_summary = "This host has OpenOffice running which is prone to multiple
  remote code execution vulnerabilities.";

if(description)
{
  script_id(800167);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-19 11:58:13 +0100 (Fri, 19 Feb 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_bugtraq_id(38218);
  script_cve_id("CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");
  script_name("OpenOffice Multiple Remote Code Execution Vulnerabilities - Feb10");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38568");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56236");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56238");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56240");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56241");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0366");

  script_description(desc);
  script_summary("Check for the version of OpenOffice");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_require_keys("OpenOffice/Win/Ver");
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

## Get the OpenOffice Version from the KB
openOffVer = get_kb_item("OpenOffice/Win/Ver");
if(!openOffVer){
  exit(0);
}

if(openOffVer != NULL)
{
  ## Check for OpenOffice Verion 3.2
  if(version_is_less(version:openOffVer, test_version:"3.2")){
    security_hole(0);
  }
}

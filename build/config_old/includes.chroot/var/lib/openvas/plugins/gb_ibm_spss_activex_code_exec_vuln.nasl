###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_spss_activex_code_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# IBM SPSS SamplePower 'VsVIEW6' ActiveX Control Multiple Code Execution Vulnerabilities (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "No solution or patch is available as of 31st January 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www-01.ibm.com/software/analytics/spss/products/statistics/samplepower/

  Workaround:
  Disable the use of the vulnerable ActiveX control within Internet Explorer.";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application using the ActiveX control. Failed
  exploit attempts will likely result in denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "IBM SPSS SamplePower version 3.0";
tag_insight = "Multiple flaws are due to unspecified errors in the VsVIEW6 ActiveX
  Control (VsVIEW6.ocx) when handling the 'SaveDoc()' and 'PrintFile()' methods.";
tag_summary = "This host is installed with IBM SPSS SamplePower and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(802600);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51448);
  script_cve_id("CVE-2012-0189");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-01 11:11:11 +0530 (Wed, 01 Feb 2012)");
  script_name("IBM SPSS SamplePower 'VsVIEW6' ActiveX Control Multiple Code Execution Vulnerabilities (Windows)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47605");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51448");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72119");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21577951");

  script_description(desc);
  script_summary("Check for the version of IBM SPSS SamplePower");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_spss_sample_power_detect_win.nasl");
  script_require_keys("IBM/SPSS/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_activex.inc");

## Get version from KB
version = get_kb_item("IBM/SPSS/Win/Ver");
if(version)
{
  ## Check for IBM SPSS SamplePower 3.0
  if(version_is_equal(version:version, test_version:"3.0"))
  {
    ## CLSID
    clsid = "{6E84D662-9599-11D2-9367-20CC03C10627}";

    ## Check if Kill-Bit is set
    if(is_killbit_set(clsid:clsid) == 0){
      security_hole(0);
    }
  }
}

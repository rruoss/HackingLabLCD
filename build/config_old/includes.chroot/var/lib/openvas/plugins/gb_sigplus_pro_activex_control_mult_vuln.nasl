###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sigplus_pro_activex_control_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Topaz Systems SigPlus Pro ActiveX Control Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to create or overwrite
  arbitrary local files and to execute arbitrary code.
  Impact Level: Application";
tag_affected = "Topaz Systems SigPlus Pro ActiveX Control Version 3.95";
tag_insight = "The flaws are due to
  - A boundary error when processing the 'KeyString' property which can be
    exploited to cause a heap-based buffer overflow via an overly long string.
  - A boundary error when processing the 'SetLocalIniFilePath()' method, and
    'SetTabletPortPath()' method can be exploited to cause a heap-based buffer
    overflow via an overly long string passed in the 'NewPath' and 'NewPortPath'
    parameter respectively.
  - An unsafe 'SetLogFilePath()' method creating a log file in a specified
    location which can be exploited in combination with the 'SigMessage()'
    method to create an arbitrary file with controlled content.";
tag_solution = "Upgrade to the Topaz Systems SigPlus Pro ActiveX Control Version 4.29
  or later.
  For updates refer to http://www.topazsystems.com/Software/download/sigplusactivex.htm";
tag_summary = "The host is installed with SigPlus Pro ActiveX Control and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(801753);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-0323", "CVE-2011-0324");
  script_bugtraq_id(46128);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Topaz Systems SigPlus Pro ActiveX Control Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42800");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65117");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2011-1/");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of SigPlus Pro ActiveX Control");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_sigplus_pro_activex_detect.nasl");
  script_require_keys("SigPlus/Ver");
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

## Get the version from KB
sigVer = get_kb_item("SigPlus/Ver");
if(!sigVer){
  exit(0);
}

## Check for SigPlus Pro ActiveX Control version equal to 3.95
if(version_is_equal(version:sigVer, test_version:"3.95")){
  security_hole(0);
}

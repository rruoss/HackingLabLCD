###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_esignal_mult_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# eSignal Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation allows execution of arbitrary code.
  Impact Level: System/Application";
tag_affected = "eSignal version 10.6.2425.1208 and prior.";
tag_insight = "- A boundary error in WinSig.exe when processing QUOTE files can be exploited
    to cause a stack-based buffer overflow.
  - A boundary error in WinSig.exe when processing the '<FaceName>' tag can be
    exploited to cause a heap-based buffer overflow via a specially crafted
    Time and Sales file.
  - The application loads libraries in an insecure manner and can be exploited
    to load arbitrary libraries by tricking a user into opening a QUOTE file
    located on a remote WebDAV or SMB share.";
tag_solution = "No solution or patch is available as of 15th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.esignal.com/esignal/default.aspx";
tag_summary = "This host is installed with eSignal and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802245);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2011-3494", "CVE-2011-3503");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("eSignal Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45966/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17837/");
  script_xref(name : "URL" , value : "http://aluigi.altervista.org/adv/esignal_1-adv.txt");

  script_description(desc);
  script_summary("Check for the version of eSignal");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_esignal_detect.nasl");
  script_require_keys("eSignal/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Get version from KB
version = get_kb_item("eSignal/Win/Ver");
if(!version){
  exit(0);
}

## Check for eSignal versions 10.6.2425.1208 and prior.
if(version_is_less_equal(version:version, test_version:"10.6.2425.1208")){
  security_hole(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_esr_mult_vuln01_oct12_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Mozilla Thunderbird ESR Multiple Vulnerabilities-01 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to conduct cross site scripting
  attacks, cause a denial of service memory corruption and application crash
  or possibly execute arbitrary code via unspecified vectors.
  Impact Level:System/Application";

tag_affected = "Thunderbird ESR versions 10.x before 10.0.8 on Mac OS X";
tag_insight = "The flaws are due to
  - memory corruption issues
  - An error within Chrome Object Wrapper (COW) when handling the
    'InstallTrigger' object can be exploited to access certain privileged
    functions and properties.
  - Use-after-free in the IME State Manager code.
  - combination of invoking full screen mode and navigating backwards in
    history could, in some circumstances, cause a hang or crash due to a
    timing dependent use-after-free pointer reference.
  - Several methods of a feature used for testing (DOMWindowUtils) are not
    protected by existing security checks, allowing these methods to be called
    through script by web pages.
  - An error when GetProperty function is invoked through JSAPI, security
    checking can be bypassed when getting cross-origin properties.
  - An issue with spoofing of the location property.
  - Use-after-free, buffer overflow, and out of bounds read issues.
  - The location property can be accessed by binary plugins through
    top.location and top can be shadowed by Object.define Property as well.
    This can allow for possible XSS attacks through plugins.
  - several memory safety bugs in the browser engine used in mozilla products.";
tag_solution = "Upgrade to Thunderbird ESR version 10.0.8 or later,
  http://www.mozilla.org/en-US/thunderbird";
tag_summary = "The host is installed with Mozilla Thunderbird ESR and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803644);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-4188", "CVE-2012-4187", "CVE-2012-4186", "CVE-2012-4185",
                "CVE-2012-4184", "CVE-2012-3982", "CVE-2012-3990", "CVE-2012-3988",
                "CVE-2012-3986", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-4183",
                "CVE-2012-4182", "CVE-2012-4181", "CVE-2012-4180", "CVE-2012-4179",
                "CVE-2012-3995", "CVE-2012-3994", "CVE-2012-3993", "CVE-2012-3983");
  script_bugtraq_id(55856);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2012-10-15 17:43:07 +0530 (Mon, 15 Oct 2012)");
  script_name("Mozilla Thunderbird ESR Multiple Vulnerabilities-01 (Mac OS X)");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50856");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50935");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-86.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-83.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-74.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-87.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-79.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-77.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-81.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-84.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-85.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-82.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-74.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-83.html");
  script_summary("Check for the vulnerable version of Mozilla Thunderbird ESR on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird-ESR/MacOSX/Version");
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

# Variable Initialization
tbVer = "";

# Thunderbird Check
tbVer = get_kb_item("ThunderBird-ESR/MacOSX/Version");
if(tbVer && tbVer =~ "^10.0")
{
  # Grep for Thunderbird version
  if(version_in_range(version:tbVer, test_version:"10.0", test_version2:"10.0.7")){
    security_hole(0);
    exit(0);
  }
}

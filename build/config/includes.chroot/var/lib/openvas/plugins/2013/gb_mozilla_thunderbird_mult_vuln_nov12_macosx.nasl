###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_thunderbird_mult_vuln_nov12_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Mozilla Thunderbird Multiple Vulnerabilities - November12 (Mac OS X)
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
tag_impact = "Successful exploitation will allow attackers to inject scripts and bypass
  certain security restrictions.
  Impact Level: Application";

tag_affected = "Thunderbird version before 16.0.2 on Mac OS X";
tag_insight = "Multiple errors
  - When handling the 'window.location' object.
  - Within CheckURL() function of the 'window.location' object, which can be
    forced to return the wrong calling document and principal.
  - Within handling of 'Location' object can be exploited to bypass security
    wrapper protection.";
tag_solution = "Upgrade to Thunderbird version to 16.0.2 or later,
  http://www.mozilla.org/en-US/thunderbird";
tag_summary = "This host is installed with Mozilla Thunderbird and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803632);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196");
  script_bugtraq_id(56301, 56302, 56306);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2012-11-02 16:08:12 +0530 (Fri, 02 Nov 2012)");
  script_name("Mozilla Thunderbird Multiple Vulnerabilities - November12 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51144");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027703");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-90.html");
  script_summary("Check for the vulnerable version of Mozilla Thunderbird on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("ThunderBird/MacOSX/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

# Thunderbird Check
tbVer = "";
tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(tbVer)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"16.0.2"))
  {
    security_hole(0);
    exit(0);
  }
}

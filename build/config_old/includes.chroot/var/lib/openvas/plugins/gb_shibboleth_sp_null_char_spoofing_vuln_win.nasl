###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_shibboleth_sp_null_char_spoofing_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Shibboleth Service Provider NULL Character Spoofing Vulnerability (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation could allow man-in-the-middle attackers to spoof
  arbitrary SSL servers via a crafted certificate by a legitimate
  Certification Authority.
  Impact Level: Application";
tag_affected = "Shibboleth Service Provider version 1.3.x before 1.3.3 and 2.x before 2.2.1
  on Windows.";
tag_insight = "The flaw exists when using PKIX trust validation. The application does not
  properly handle a '\0' character in the subject or subjectAltName fields
  of a certificate.";
tag_solution = "Upgrade Shibboleth Service Provider version 1.3.3 or 2.2.1 or later
  http://shibboleth.internet2.edu/downloads.html";
tag_summary = "The host has Shibboleth Service Provider installed and is prone to
  NULL Character Spoofing vulnerability.";

if(description)
{
  script_id(801116);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3475");
  script_name("Shibboleth Service Provider NULL Character Spoofing Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36861/");
  script_xref(name : "URL" , value : "http://shibboleth.internet2.edu/secadv/secadv_20090817.txt");

  script_description(desc);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_summary("Check for the version of Shibboleth Service Provider");
  script_family("General");
  script_dependencies("gb_shibboleth_sp_detect_win.nasl");
  script_require_keys("Shibboleth/SP/Win/Ver");
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

shibVer = get_kb_item("Shibboleth/SP/Win/Ver");
if(!shibVer){
  exit(0);
}

# Check for Shibboleth Service Provider version 1.3.x < 1.3.3 and 2.x < 2.2.1
if(version_in_range(version:shibVer, test_version:"1.3", test_version2:"1.3.2")||
   version_in_range(version:shibVer, test_version:"2.0", test_version2:"2.2.0")){
  security_hole(0);
}

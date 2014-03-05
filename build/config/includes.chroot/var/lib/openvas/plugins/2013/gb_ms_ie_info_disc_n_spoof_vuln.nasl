###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_info_disc_n_spoof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# MS IE Information Disclosure and Web Site Spoofing Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows attackers to disclose the sensitive
  information and view the contents of spoofed site or carry out phishing
  attacks.
  Impact Level: Application";

tag_affected = "Microsoft Internet Explorer versions 8 and 9";
tag_insight = "The proxy settings configuration has same proxy address and value for HTTP
  and HTTPS,
  - TCP session to proxy sever will not properly be reused. This allows remote
    attackers to steal cookie information via crafted HTML document.
  - SSl lock consistency with address bar is not ensured. This allows remote
    attackers to spoof web sites via a crafted HTML document.";
tag_solution = "No solution or patch is available as of 04th February, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://ie.microsoft.com";
tag_summary = "This host is installed with Microsoft Internet Explorer and is
  prone to information disclosure and web site spoofing vulnerabilities.";

if(description)
{
  script_id(803305);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57640, 57641);
  script_cve_id("CVE-2013-1450","CVE-2013-1451");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-04 11:45:52 +0530 (Mon, 04 Feb 2013)");
  script_name("MS IE Information Disclosure and Web Site Spoofing Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://pastebin.com/raw.php?i=rz9BcBey");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2013-1450");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2013-1451");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-1450");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-1451");

  script_description(desc);
  script_summary("Check the vulnerable version of Microsoft Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


# Variable Initialization
ieVer = "";

# Check for product Internet Explorer
ieVer = get_kb_item("MS/IE/Version");

# Check for Internet Explorer version
if(ieVer && ieVer =~ "^(8|9)"){
  security_warning(0);
}

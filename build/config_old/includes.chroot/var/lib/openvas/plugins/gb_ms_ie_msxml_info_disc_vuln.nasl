###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_msxml_info_disc_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Internet Explorer 'msxml.dll' Information Disclosure Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to gain access to sensitive
  information that may aid in further attacks.
  Impact Level: Application";
tag_affected = "Microsoft Internet Explorer version 8 on Windows 7.";
tag_insight = "The flaw is due to an error in msxml.dll allows remote attackers to
  obtain potentially sensitive information about heap memory addresses via an
  XML document containing a call to the XSLT generate-id XPath function.";
tag_solution = "No solution or patch is available as of 20th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host is installed with Internet Explorer and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(801876);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-1713");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft Internet Explorer 'msxml.dll' Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2011/03/multi-browser-heap-address-leak-in-xslt.html");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_require_ports(139, 445);
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
include("secpod_reg.inc");
include("version_func.inc");

## Check for Windows 7
if(hotfix_check_sp(win7:2) <= 0){
  exit(0);
}

## Get IE Version from KB
ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

## Check for IE version 8
if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.7600.16766")){
  security_warning(0);
}
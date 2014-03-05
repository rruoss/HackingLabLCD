###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_src_iframe_dos_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Opera Browser 'SRC' Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Opera Web Browser version 11.11 on Mac OS X.";
tag_insight = "The flaw is due to setting the FACE attribute of a FONT element within
  an IFRAME element after changing the SRC attribute of this IFRAME element to
  an about:blank value.";
tag_solution = "No solution or patch is available as of 19th April, 2012. Information
  regarding this issue will be updated once the solution details are available
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera browser and is prone to denial of
  service Vulnerability.";

if(description)
{
  script_id(802757);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-2641");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-19 11:40:12 +0530 (Thu, 19 Apr 2012)");
  script_name("Opera Browser 'SRC' Denial of Service Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17396/");

  script_description(desc);
  script_summary("Check for the version of Opera on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_opera_detect_macosx.nasl");
  script_require_keys("Opera/MacOSX/Version");
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

## Get Opera Version from KB
operaVer = get_kb_item("Opera/MacOSX/Version");
if(!operaVer){
  exit(0);
}

## Grep for Opera Version equals to 11.11
if(version_is_equal(version:operaVer, test_version:"11.11")){
  security_warning(0);
}


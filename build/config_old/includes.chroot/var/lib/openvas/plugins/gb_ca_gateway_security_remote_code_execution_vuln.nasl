###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ca_gateway_security_remote_code_execution_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CA Gateway Security Remote Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code and cause denail of service.
  Impact Level: System/Application";
tag_affected = "CA Gateway Security 8.1";
tag_insight = "The flaw is due to an error in the Icihttp.exe module, which can be
  exploited by sending a specially-crafted HTTP request to TCP port 8080.";
tag_solution = "Apply patch for CA Gateway Security r8.1
  https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={5E404992-6B58-4C44-A29D-027D05B6285D}";
tag_summary = "This host is installed with CA Gateway Security and is prone to
  remote code execution Vulnerability.";

if(description)
{
  script_id(802337);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-0419");
  script_bugtraq_id(48813);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-15 12:35:07 +0530 (Tue, 15 Nov 2011)");
  script_name("CA Gateway Security Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45332");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025812");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025813");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68736");
  script_xref(name : "URL" , value : "https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={5E404992-6B58-4C44-A29D-027D05B6285D}");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of CA Gateway Security");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_ca_mult_prdts_detect_win.nasl");
  script_require_keys("CA/Gateway-Security/Win/Ver");
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

## Get version from KB
cagsver = get_kb_item("CA/Gateway-Security/Win/Ver");
if(!cagsver){
  exit(0);
}

## Check for CA Gateway Security Version less than 8.1.0.69
if(version_is_less(version:cagsver, test_version:"8.1.0.69")){
  security_warning(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_releaseinterface_code_execution_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft IE 'ReleaseInterface()' Remote Code Execution Vulnerability
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
tag_impact = "Successful exploits allows an attacker to run arbitrary code in the
  context of the user running the application. Failed attacks will cause
  denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 8.0.7600.16385";
tag_insight = "The flaw is caused by a use-after-free error within the 'mshtml.dll' library
  when handling circular references between JScript objects and Document Object
  Model (DOM) objects, which could allow remote attackers to execute arbitrary
  code via a specially crafted web page.";
tag_solution = "No solution or patch is available as of 27th January, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host is installed with Internet Explorer and is prone to
  remote code execution vulnerability.";

if(description)
{
  script_id(801830);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2011-0346");
  script_bugtraq_id(45639);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Internet Explorer 'ReleaseInterface()' Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/427980");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64482");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024940");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0026");

  script_description(desc);
  script_summary("Check for the version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
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


include("version_func.inc");

## Get IE version from KB
ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

## Check Internet Explorer version 8.0.7600.16385
if(version_is_equal(version:ieVer, test_version:"8.0.7600.16385")){
  security_hole(0);
}
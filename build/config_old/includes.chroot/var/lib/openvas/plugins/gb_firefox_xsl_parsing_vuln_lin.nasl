###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_xsl_parsing_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Firefox XSL Parsing Vulnerability (Linux)
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
tag_impact = "Successful exploitation will let the attacker cause remote code execution
  through a specially crafted malicious XSL file or can cause application
  termination at runtime.
  Impact Level: System/Application";
tag_affected = "Firefox version 3.0 to 3.0.7 on Linux.";
tag_insight = "This flaw is due to improper handling of errors encountered when transforming
  an XML document which can be exploited to cause memory corrpution through a
  specially crafted XSLT code.";
tag_solution = "Upgrade to Firefox version 3.0.8
  http://www.mozilla.com/en-US/firefox/firefox.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone
  to XSL File Parsing Vulnerability.";

if(description)
{
  script_id(800377);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1169");
  script_bugtraq_id(34235);
  script_name("Firefox XSL Parsing Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34471");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8285");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Mar/1021941.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-12.html");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Grep for firefox version 3.0 to 3.0.7
if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.7")){
  security_hole(0);
}

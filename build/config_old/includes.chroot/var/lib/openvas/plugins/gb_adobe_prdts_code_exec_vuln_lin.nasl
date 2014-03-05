###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_code_exec_vuln_lin.nasl 16 2013-10-27 13:09:52Z jan $
#
# Adobe Reader/Acrobat JavaScript Method Handling Vulnerability (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  or an attacker could take complete control of an affected system or cause
  a denial of service condition.
  Impact Level: System";
tag_summary = "This host has Adobe Reader/Acrobat installed, which is/are prone
  to Remote Code Execution Vulnerabilities.";

tag_affected = "Adobe Reader version 7.0.9 and prior - Linux(All)
  Adobe Reader versions 8.0 through 8.1.2 - Linux(All)";
tag_insight = "The flaw is due to an input validation error in a JavaScript method,
  which could allow attackers to execute arbitrary code by tricking a user
  into opening a specially crafted PDF document.";
tag_solution = "Apply Security Update mentioned in the advisory from the below link,
  http://www.adobe.com/support/security/bulletins/apsb08-15.html";

if(description)
{
  script_id(800107);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-04 09:54:24 +0200 (Sat, 04 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-2641");
  script_bugtraq_id(29908);
  script_xref(name:"CB-A", value:"08-0105");
  script_name("Adobe Reader/Acrobat JavaScript Method Handling Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/43307");
  script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/1906/products");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb08-15.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("login/SSH/success","Adobe/Reader/Linux/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


adobeVer = get_kb_item("Adobe/Reader/Linux/Version");
if(!adobeVer){
  exit(0);
}

# Security Update 1 (SU1) is applied
if(adobeVer =~ "8.1.2_SU[0-9]+"){
  exit(0);
}

if(adobeVer =~ "^(7\.0(\.[0-9])?|8\.0(\..*)?|8\.1(\.[0-2])?)$"){
  security_hole(0);
}
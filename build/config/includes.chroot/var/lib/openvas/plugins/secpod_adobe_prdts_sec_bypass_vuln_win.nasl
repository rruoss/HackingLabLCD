###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_sec_bypass_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Adobe Reader/Acrobat Security Bypass Vulnerability (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows attackers to bypass intended security
  restrictions, which may leads to the other attacks.
  Impact Level: System/Application";
tag_summary = "This host has Adobe Reader/Acrobat installed, and is/are prone
  to security bypass vulnerability.";

tag_affected = "Adobe Reader version 10.0.1 and prior.
  Adobe Acrobat version 10.0.1 and prior.";
tag_insight = "The flaw is caused by an unknown vectors,allows attackers to bypass intended
  access restriction.";
tag_solution = "Upgrade to Adobe Acrobat and Reader version 10.1 or later
  For updates refer to http://www.adobe.com/support/downloads/product.jsp?product=10&platform=Windows";

if(description)
{
  script_id(902387);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2102");
  script_bugtraq_id(48253);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader/Acrobat Security Bypass Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb11-16.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Acrobat/Win/Ver", "Adobe/Reader/Win/Ver");
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

readerVer = get_kb_item("Adobe/Reader/Win/Ver");
if(readerVer != NULL)
{
  ## Check for Adobe Reader versions
  if(readerVer =~ "10\.") {
    if(version_is_less(version:readerVer, test_version:"10.1")) {
      security_hole(0);
      exit(0);
    }
  }  

  if(readerVer =~ "9\.") {
    if(version_is_less(version:readerVer, test_version:"9.4.5")) {
      security_hole(0);
      exit(0);
    }
  }        

  if(readerVer =~ "8\.") {
    if(version_is_less(version:readerVer, test_version:"8.3")) {
      security_hole(0);
      exit(0);
    }

  }

}

acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer != NULL)
{

  if(acrobatVer =~ "10\.") {
    if(version_is_less(version:acrobatVer, test_version:"10.1")) {
      security_hole(0);
      exit(0);
    }  
  }  

  if(acrobatVer =~ "9\.") {
    if(version_is_less(version:acrobatVer, test_version:"9.4.5")) {
      security_hole(0);
      exit(0);
    }
  } 

  if(acrobatVer =~ "8\.") {
    if(version_is_less(version:acrobatVer, test_version:"8.3")) {
      security_hole(0);
      exit(0);
    }
  }

}

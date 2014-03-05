###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_blackberry_desktop_sec_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# BlackBerry Desktop Software Information Disclosure Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that may lead to further attacks.
  Impact Level: Application";
tag_affected = "BlackBerry Desktop Software version 4.7 through 6.0";
tag_insight = "The flaw is due to a 'weak password method' used in the BlackBerry
  Desktop Software, which allows to conduct brute force guessing attacks to
  decrypt the backup file.";
tag_solution = "Upgrade to the BlackBerry Desktop Software version 6.0.1 or later,
  For updates refer to http://uk.blackberry.com/services/desktop/desktop_pc.jsp";
tag_summary = "This host is installed with BlackBerry Desktop Software and is prone
  to Information Disclosure vulnerability.";

if(description)
{
  script_id(902329);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-01 16:46:08 +0100 (Tue, 01 Feb 2011)");
  script_cve_id("CVE-2010-2603");
  script_bugtraq_id(45434);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("BlackBerry Desktop Software Information Disclosure Vulnerability");
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
  script_summary("Check for the version of BlackBerry Desktop Software");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_blackberry_desktop_software_detect_win.nasl");
  script_require_keys("BlackBerry/Desktop/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42657");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024908");
  script_xref(name : "URL" , value : "http://www.blackberry.com/btsc/search.do?cmd=displayKC&amp;docType=kc&amp;externalId=KB24764");
  exit(0);
}


include("version_func.inc");

bbdVer = get_kb_item("BlackBerry/Desktop/Win/Ver");
if(!bbdVer){
  exit(0);
}

# Check for BlackBerry Desktop Software version 4.7 through 6.0
if(version_in_range(version:bbdVer, test_version:"4.7", test_version2:"6.0.0.43")){
  security_warning(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_iprint_client_mult_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Novell iPrint Client Multiple Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code, to
  cause buffer overflow or cause the application to crash.
  Impact Level: Application";
tag_affected = "Novell iPrint Client version prior to 5.44 on Windows";
tag_insight = "Multiple flaws are due to:
  - An error in 'PluginGetDriverFile' function, which interprets an uninitialized
    memory location as a pointer value.
  - An improper bounds checking by the 'call-back-url' parameter for a
    'op-client-interface-version' operation. A remote attacker can use an overly
    long call-back-url parameter to overflow a buffer and execute arbitrary code
    on the system.";
tag_solution = "Upgrade to Novell iPrint Client version 5.44 or later
  http://www.novell.com/products/openenterpriseserver/iprint.html";
tag_summary = "The host is installed with Novell iPrint Client and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(902098);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:09:21 +0200 (Mon, 30 Aug 2010)");
  script_cve_id("CVE-2010-3105", "CVE-2010-1527");
  script_bugtraq_id(42576);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Novell iPrint Client Multiple Vulnerabilities (windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40805");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61220");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-104/");
  script_xref(name : "URL" , value : "http://www.novell.com/support/viewContent.do?externalId=7006679");

  script_description(desc);
  script_copyright("Copyright (c) 2010 SecPod");
  script_summary("Check the version of Novell iPrint Client");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_require_keys("Novell/iPrint/Ver");
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

## Get the version from KB
iPrintVer = get_kb_item("Novell/iPrint/Ver");
if(!iPrintVer){
  exit(0);
}

## Check for Novell iPrint Client Version < 5.44
if(version_is_less(version:iPrintVer, test_version:"5.44")){
  security_hole(0);
}

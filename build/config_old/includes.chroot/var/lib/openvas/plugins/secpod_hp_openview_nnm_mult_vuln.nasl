###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_openview_nnm_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP OpenView Network Node Manager Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2010-09-28
#  Added the related CVE and description.
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
tag_solution = "Apply the patch for OpenView NNM version 7.53,
  http://seclists.org/bugtraq/2010/Jun/152
  http://support.openview.hp.com/selfsolve/patches
  http://marc.info/?l=bugtraq&m=128525454219838&w=2

  *****
  NOTE : No Patch/Solution available for OpenView NNM version 7.51, upgrade to
         OpenView NNM version 7.53 and apply the patch.
  *****

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to cause a buffer overflow
  via a specially crafted HTTP request to the 'jovgraph.exe' CGI program.
  Impact Level: System/Application";
tag_affected = "HP OpenView Network Node Manager version 7.51 and 7.53";
tag_insight = "The flaws are due to boundary errors,
  - when creating an error message within 'ovwebsnmpsrv.exe'
  - within 'getProxiedStorageAddress()' in 'ovutil.dll'
  - when parsing command line argument variables within 'ovwebsnmpsrv.ex'
  And an unspecified vulnerability allows remote attackers to cause a denial
  of service via unknown vectors.";
tag_summary = "This host is running HP OpenView Network Node Manager and
  is prone to multiple vulnerabilities.";

if(description)
{
  script_id(902076);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-22 14:43:46 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-1964", "CVE-2010-1961", "CVE-2010-1960", "CVE-2010-3285");
  script_bugtraq_id(40873, 40637, 40638);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("HP OpenView Network Node Manager Multiple Vulnerabilities");
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
  script_summary("Check version of HP OpenView Network Node Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40101");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59250");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59249");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2010/Jun/152");
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=128525454219838&amp;w=2");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jun/1024071.html");
  exit(0);
}


include("version_func.inc");

## Check NNM Port status
nnmPort = 7510;
if(!get_port_state(nnmPort)){
  exit(0);
}

## Get HP OpenView Network Node Manager version from KB
nnmVer = get_kb_item(string("www/", nnmPort, "/HP/OVNNM/Ver"));
if(nnmVer != NULL)
{
  ## Check for HP OpenView Network Node Manager equal to 07.51 and 07.53
  if(version_is_equal(version:nnmVer, test_version:"B.07.51") ||
     version_is_equal(version:nnmVer, test_version:"B.07.53")){
    security_hole(nnmPort);
  }
}

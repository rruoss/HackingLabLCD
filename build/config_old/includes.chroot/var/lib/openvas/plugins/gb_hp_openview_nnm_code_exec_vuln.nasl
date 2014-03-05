###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_openview_nnm_code_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP OpenView Network Node Manager Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply the patch from below link,
  http://support.openview.hp.com/selfsolve/patches

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.
  Impact Level: System/Application";
tag_affected = "HP OpenView Network Node Manager versions 7.01, 7.51 and 7.53";
tag_insight = "The flaw is due to an unspecified error when processing specially crafted
  data, which could allow remote attackers to crash an affected process or
  execute arbitrary code via a malicious request.";
tag_summary = "This host is running HP OpenView Network Node Manager and
  is prone to code execution vulnerabilities.";

if(description)
{
  script_id(801389);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(34812);
  script_cve_id("CVE-2009-0720");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("HP OpenView Network Node Manager Code Execution Vulnerability");
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
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_xref(name : "URL" , value : "http://osvdb.org/54222");
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&amp;m=124146030732511&amp;w=2");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/May/1022163.html");
  exit(0);
}


include("http_func.inc");
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
  ## Check for HP OpenView Network Node Manager equal to 7.01, 7.51 and 07.53
  if(version_is_equal(version:nnmVer, test_version:"B.07.51") ||
     version_is_equal(version:nnmVer, test_version:"B.07.53") ||
     version_is_equal(version:nnmVer, test_version:"B.07.01")){
   security_hole(nnmPort);
  }
}

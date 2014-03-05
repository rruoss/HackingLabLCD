###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_openview_nnm_mult_code_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# HP OpenView Network Node Manager Multiple Code Execution Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-08-06
#  -Added CVE-2010-2709 Related BID and description.
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
tag_solution = "Upgrade to NNM v7.53 and apply the patch
  http://support.openview.hp.com/selfsolve/patches

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.
  Impact Level: System/Application";
tag_affected = "HP OpenView Network Node Manager 7.51 and 7.53";
tag_insight = "The multiple flaws are due to,
   - A buffer overflow error in 'CGI' executable when processing an overly long
     parameter value.
   - A buffer overflow error in the 'ov.dll' library when processing certain
     arguments supplied via CGI executables.
   - An error in 'webappmon.exe' CGI application, which fails to adequately
     validate user-supplied input.";
tag_summary = "This host is running HP OpenView Network Node Manager and
  is prone to multiple code execution vulnerabilities.";

if(description)
{
  script_id(801388);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_cve_id("CVE-2010-2704", "CVE-2010-2709");
  script_bugtraq_id(41839, 42154);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("HP OpenView Network Node Manager Multiple Code Execution Vulnerabilities");
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

  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512508");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1866");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02290344");

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
  ## Check for HP OpenView Network Node Manager equal to 7.51 and 07.53
  if(version_is_equal(version:nnmVer, test_version:"B.07.51") ||
     version_is_equal(version:nnmVer, test_version:"B.07.53")){
   security_hole(nnmPort);
  }
}

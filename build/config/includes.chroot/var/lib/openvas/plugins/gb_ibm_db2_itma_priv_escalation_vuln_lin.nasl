###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_itma_priv_escalation_vuln_lin.nasl 12 2013-10-27 11:15:33Z jan $
#
# IBM DB2 Tivoli Monitoring Agent Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow local users to perform certain actions
  with escalated privileges and gain sensitive information.
  Impact Level: Application";
tag_affected = "IBM DB2 version 9.5 through FP8";
tag_insight = "The flaw is due to an unspecified error in Tivoli Monitoring Agent.";
tag_solution = "Upgrade to IBM DB2 version 9.5 FP9 or later,
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg21588098";
tag_summary = "This host is installed with IBM DB2 and is prone to privilege
  escalation vulnerability.";

if(description)
{
  script_id(802735);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1796");
  script_bugtraq_id(52326);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-06 16:59:20 +0530 (Fri, 06 Apr 2012)");
  script_name("IBM DB2 Tivoli Monitoring Agent Privilege Escalation Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48279/");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21586193");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC79970");

  script_description(desc);
  script_summary("Check for the Version of IBM DB2 Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_ibm_db2_detect_linux_900217.nasl");
  script_require_keys("Linux/IBM_db2/Ver");
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

## Variable Initialization
ibmVer = "";

ibmVer = get_kb_item("Linux/IBM_db2/Ver");
if(ibmVer == NULL){
  exit(0);
}

## Check for IBM DB2 Version 9.5 before 9.5 FP8 (IBM DB2 9.5 FP5 = 9.5.0.8)
if(version_in_range(version:ibmVer, test_version:"9.5", test_version2:"9.5.0.8")){
  security_hole(0);
}

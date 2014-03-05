###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_bof_vuln_lin_feb10.nasl 14 2013-10-27 12:33:37Z jan $
#
# IBM DB2 'REPEAT()' Heap Buffer Overflow Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code with
  elevated privileges or crash the affected application.
  Impact Level: System/Application";
tag_affected = "IBM DB2 version 9.7.1 and prior.";
tag_insight = "The flaw is due to error in 'REPEAT()' function when processing SELECT statement
  that has a long column name generated.";
tag_solution = "No solution or patch is available as of 01st February, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www-01.ibm.com/software/data/db2/express/download.html";
tag_summary = "The host is installed with IBM DB2 and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_id(800448);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0462");
  script_bugtraq_id(37976);
  script_name("IBM DB2 'REPEAT()' Heap Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "httphttp://xforce.iss.net/xforce/xfdb/55899");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jan/1023509.html");
  script_xref(name : "URL" , value : "http://intevydis.blogspot.com/2010/01/ibm-db2-97-heap-overflow.html");

  script_description(desc);
  script_summary("Check for the version of IBM DB2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Databases");
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

ibmVer = get_kb_item("Linux/IBM_db2/Ver");
if(!ibmVer){
  exit(0);
}

# Check for IBM DB2 Version 9.7.1(9.7.0.1)and prior.
if(version_in_range(version:ibmVer, test_version:"9.7", test_version2:"9.7.0.1")){
  security_hole(0);
}

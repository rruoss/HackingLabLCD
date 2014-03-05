###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_das_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# IBM DB2 Administration Server (DAS) Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote users to cause denial
  of service or execution of abritrary code.
  Impact Level: Application.";
tag_affected = "IBM DB2 version 9.1 before FP10,
  IBM DB2 version 9.5 before FP7 and
  IBM DB2 version 9.7 before FP3";
tag_insight = "The flaw is due to a boundary error in the 'receiveDASMessage()'
  function in 'db2dasrrm' and can be exploited to cause a heap-based buffer
  overflow via a specially crafted request sent to TCP port 524.";
tag_solution = "Upgrade to IBM DB2 version 9.1 FP10, 9.5 FP7, 9.7 FP3 or later,
  http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";
tag_summary = "The host is running IBM DB2 and is prone to buffer overflow
  vulnerability.";

if(description)
{
  script_id(801589);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_bugtraq_id(46052);
  script_cve_id("CVE-2011-0731");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("IBM DB2 Administration Server (DAS) Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70683");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43059");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg1IC72029");
  script_xref(name : "URL" , value : "https://www-304.ibm.com/support/docview.wss?uid=swg1IC72028");

  script_description(desc);
  script_summary("Check for the version of IBM DB2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_require_keys("IBM-DB2/Remote/ver");
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

ibmVer = get_kb_item("IBM-DB2/Remote/ver");
if(!ibmVer){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 FP 3 => 09073
  if(version_is_less(version:ibmVer, test_version:"09073"))
  {
    security_hole(0);
    exit(0);
  }
}

if(ibmVer =~ "^0901\.*")
{
  # IBM DB2 9.1 FP 10 => 090110
  if(version_is_less(version:ibmVer, test_version:"090110"))
  {
    security_hole(0);
    exit(0);
  }
}

if(ibmVer =~ "^0905\.*")
{
  # IBM DB2 9.5 FP 7 => 09057
  if(version_is_less(version:ibmVer, test_version:"09057")){
    security_hole(0);
  }
}

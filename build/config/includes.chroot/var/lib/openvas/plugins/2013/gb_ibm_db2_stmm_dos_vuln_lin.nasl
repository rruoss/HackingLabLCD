###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_stmm_dos_vuln_lin.nasl 11 2013-10-27 10:12:02Z jan $
#
# IBM DB2 STMM Denial Of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803766";
CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2011-1373");
  script_bugtraq_id(50686);
  script_tag(name:"cvss_base", value:"1.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Low");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-30 17:51:03 +0530 (Mon, 30 Sep 2013)");
  script_name("IBM DB2 STMM Denial Of Service Vulnerability (Linux)");

   tag_summary =
"This host is running IBM DB2 and is prone to denial of service vulnerability.";

  tag_vuldetect =
"Get the installed version of IBM DB2 with the help of detect NVT and check
the version is vulnerable or not.";

  tag_insight =
"The flaw is due an error when the Self Tuning Memory Manager (STMM) feature
and the AUTOMATIC DATABASE_MEMORY setting are configured.";

  tag_impact =
"Successful exploitation will allow attacker to allows local users to cause a
denial of service (daemon crash) via unknown vectors.

Impact Level: Application";

  tag_affected =
"IBM DB2 version 9.7 before FP5 on Linux.";

  tag_solution =
"Upgrade to IBM DB2 9.7 FP5 or later,
For updates refer to http://www-01.ibm.com ";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/77204");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71043");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1IC70473");
  script_summary("Check for the vulnerable version of IBM DB2 on Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl", "os_fingerprint.nasl");
  script_mandatory_keys("IBM-DB2/installed");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(host_runs("Linux") != "yes"){
  exit(0);
}

## Variable Initialization
ibmVer  = "";
ibmPort = "";

if(!ibmPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(!ibmVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ibmPort)){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  ## IBM DB2 version 9.7.x before FP5,
  if(version_is_less(version:ibmVer, test_version:"09075"))
  {
    security_note(port:ibmPort);
    exit(0);
  }
}

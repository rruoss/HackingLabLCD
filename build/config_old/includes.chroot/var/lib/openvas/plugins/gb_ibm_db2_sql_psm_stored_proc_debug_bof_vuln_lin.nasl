###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_db2_sql_psm_stored_proc_debug_bof_vuln_lin.nasl 12 2013-10-27 11:15:33Z jan $
#
# IBM DB2 SQL/PSM Stored Procedure Debugging Buffer Overflow Vulnerability (Linux)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_affected = "IBM DB2 versions 9.1, 9.5, 9.7 before FP7, 9.8 and 10.1 on Linux

  NOTE : Ignore the security hole if IBM DB2 pureScale Feature on IBM DB2 version
         9.8 is not installed.";

tag_solution = "Upgrade to IBM DB2 version 9.7 FP7 or later,
  For updates refer, http://www-01.ibm.com/support/docview.wss?uid=swg24033685

  ******
  NOTE : A special build with the interim fix will be made available for
         DB2 V9.5 FP10, V9.8 FP5 and V10.1 FP1.
  ******";

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code.
  Impact Level: Application";
tag_insight = "The Stored Procedure (SP) infrastructure fails to properly sanitize
  user-supplied input when debugging stored procedures, which will result
  in a stack-based buffer overflow.";
tag_summary = "The host is running IBM DB2 and is prone to buffer overflow
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803107";
CPE = "cpe:/a:ibm:db2";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4826");
  script_bugtraq_id(56133);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-25 11:58:30 +0530 (Thu, 25 Oct 2012)");
  script_name("IBM DB2 SQL/PSM Stored Procedure Debugging Buffer Overflow Vulnerability (Linux)");
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

  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/86414");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50921/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78817");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21450666");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21614536");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg24033685");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg27007053");

  script_description(desc);
  script_summary("Check for the version of IBM DB2 on Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("IBM-DB2/Remote/ver");
  script_require_keys("IBM-DB2/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

## Variable Initialization
vers = "";
ibmVer  = "";

## Check for windows platform
if(host_runs("Linux") != "yes"){
 exit(0);
}

## Get the port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get IBM DB2 version
if(!ibmVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 FP 7 > 09077
  if(version_is_less(version:ibmVer, test_version:"09077"))
  {
    security_hole(port);
    exit(0);
  }
}

if(ibmVer =~ "^0901\.*")
{
  # IBM DB2 9.1 FP12 => 090112
  if(version_is_less_equal(version:ibmVer, test_version:"090112"))
  {
    security_hole(port);
    exit(0);
  }
}

if(ibmVer =~ "^0905\.*")
{
  # IBM DB2 9.5 FP10 => 090510
  if(version_is_less_equal(version:ibmVer, test_version:"090510"))
  {
    security_hole(port);
    exit(0);
  }
}

if(ibmVer =~ "^0908\.*")
{
  # IBM DB2 9.8 FP5 => 09085
  if(version_is_less_equal(version:ibmVer, test_version:"09085"))
  {
    security_hole(port);
    exit(0);
  }
}

if(ibmVer =~ "^1001.*")
{
  # IBM DB2 10.1 FP1 => 10011
  if(version_is_less_equal(version:ibmVer, test_version:"10011")){
    security_hole(port);
  }
}
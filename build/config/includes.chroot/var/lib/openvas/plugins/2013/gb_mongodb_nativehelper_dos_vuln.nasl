###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_nativehelper_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# MongoDB nativeHelper Denial of Service Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803951";
CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1892");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-07 15:50:02 +0530 (Mon, 07 Oct 2013)");
  script_name("MongoDB nativeHelper Denial of Service Vulnerability");

  tag_summary =
"This host is running MongoDB and is prone to a denial of service vulnerability.";

  tag_vuldetect =
"Get the installed version of MongoDB with the help of detect NVT and check the
version is vulnerable or not.";

  tag_insight =
"An error exists in nativeHelper function in SpiderMonkey which fails to
validate requests properly.";

  tag_impact =
"Successful exploitation will allow remote authenticated users to cause a
denial of service condition or execute arbitrary code via a crafted memory
address in the first argument.

Impact Level: System/Application";

tag_affected =
"MongoDB version before 2.0.9 and 2.2.x before 2.2.4";

tag_solution =
"Upgrade to MongoDB version 2.0.9 or 2.2.4 or 2.4.2 or later,
For updates refer to http://www.mongodb.org";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/91632");
  script_xref(name : "URL" , value : "http://www.mongodb.org/about/alerts");
  script_xref(name : "URL" , value : "https://jira.mongodb.org/browse/SERVER-9124");
  script_summary("Determine if installed MongoDB version is vulnerable");
  script_category(ACT_GATHER_INFO);
  script_family("Databases");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_mongodb_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/mongodb", 27017);
  script_mandatory_keys("mongodb/installed");
  exit(0);
}


include("version_func.inc");
include("misc_func.inc");
include("host_details.inc");

function check_mongodb_ver(mongodbversion, mongodbPort)
{
  ## check the version
  if(version_is_less(version: mongodbversion, test_version: "2.0.9") ||
     version_in_range(version: mongodbversion, test_version:"2.2.0", test_version2:"2.2.3"))
  {
    security_hole(mongodbPort);
    exit(0);
  }
}

## Variable initialisation
port = "";
ver = "";

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

if(!get_tcp_port_state(port))exit(0);

if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## windows
if(host_runs("Windows") == "yes"){
  check_mongodb_ver(mongodbversion:ver, mongodbPort:port);
}

## Linux with backport issue
if(get_kb_item("mongodb/paranoia")){
  check_mongodb_ver(mongodbversion:ver, mongodbPort:port);
}

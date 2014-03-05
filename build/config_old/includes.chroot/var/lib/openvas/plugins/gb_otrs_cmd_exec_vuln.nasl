##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_cmd_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Open Ticket Request System (OTRS) Command Execution Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801766";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-0456");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_name("Open Ticket Request System (OTRS) Command Execution Vulnerability");

tag_summary =
"This host is running Open Ticket Request System (OTRS) and is prone to command
execution bulnerability.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"The flaw is due to certain unspecified input is not properly sanitised before
being used. This can be exploited to inject and execute shell commands.";

tag_impact =
"Successful exploitation will allow attackers to execute an arbitrary OS
command with the privileges of OTRS on the server where it is installed.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version prior to 2.3.5";

tag_solution =
"Upgarde to Open Ticket Request System (OTRS) version 2.3.5 or later,
For updates refer to http://otrs.org/download/";


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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38507/");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN73162541/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000019.html");
  script_summary("Check for the version of Open Ticket Request System (OTRS)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialisation
port = "";
vers = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  if(version_is_less_equal(version:vers, test_version:"2.3.4"))
  {
    security_hole(otrsPort);
  }
}

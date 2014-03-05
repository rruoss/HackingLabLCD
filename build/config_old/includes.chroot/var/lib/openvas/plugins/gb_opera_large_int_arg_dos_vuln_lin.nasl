###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_large_int_arg_dos_vuln_lin.nasl 12 2013-10-27 11:15:33Z jan $
#
# Opera Large Integer Argument Denial of Service Vulnerability (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation may allow remote attackers to cause a denial
  of service via a large integer argument.
  Impact Level: Application";
tag_affected = "Opera version 11.60 and prior on Linux";
tag_insight = "The flaw is due to an improper handling of argument sent to the
  functions Int32Array, Float32Array, Float64Array, Uint32Array, Int16Array
  or ArrayBuffer, which can be exploited to crash the Opera via a large
  integer argument to these functions.";
tag_solution = "No solution or patch is available as of 06th, April 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera and is prone to denial of service
  vulnerability.";

if(description)
{
  script_id(802829);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1003");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date");
  script_tag(name:"creation_date", value:"2012-04-06 11:53:30 +0530 (Fri, 06 Apr 2012)");
  script_name("Opera Large Integer Argument Denial of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/419678.php");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/73027");
  script_xref(name : "URL" , value : "http://blog.vulnhunt.com/index.php/2012/02/02/cal-2012-0004-opera-array-integer-overflow/");

  script_description(desc);
  script_summary("Check for the version of Opera on Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
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
operaVer = NULL;

## Get the version
operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

## Check for opera version < 11.60
if(version_is_less_equal(version:operaVer, test_version:"11.60")){
  security_warning(0);
}

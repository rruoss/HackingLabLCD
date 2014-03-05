###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_dos_vuln_jun09.nasl 15 2013-10-27 12:49:54Z jan $
#
# CUPS Denial of Service Vulnerability - Jun09
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  and can cause denial of service.
  Impact Level: System/Application";
tag_affected = "CUPS versions prior to 1.2.0 and 1.3.7 on Linux";
tag_insight = "The flaws are due to
  - A use-after-free error within the directory-services functionality in the
    scheduler.
  - Integer overflow errors within the 'pdftops' filter while processing
    specially crafted PDF file.";
tag_solution = "No solution or patch is available as of 15th June, 2009. Information
  regarding this issue will be updated once the solution details are available.
  http://www.cups.org/software.php";
tag_summary = "This host is running CUPS (Common UNIX Printing System) Service,
  which is prone to Denial of Service vulnerability.";

if(description)
{
  script_id(800584);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-16 15:11:01 +0200 (Tue, 16 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1196", "CVE-2009-0791");
  script_bugtraq_id(35194, 35195);
  script_name("CUPS Denial of Service Vulnerability - Jun09");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35340");
  script_xref(name : "URL" , value : "http://rhn.redhat.com/errata/RHSA-2009-1083.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2009/Jun/1022327.html");

  script_description(desc);
  script_summary("Check for the version of CUPS Service");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

cupsPort = get_http_port(default:631);
if(!cupsPort){
  exit(0);
}

cupsVer = get_kb_item("www/"+ cupsPort + "/CUPS");
if(!cupsVer){
  exit(0);
}

if(cupsVer != NULL)
{
  # Check for CUPS version prior to 1.2.0 and 1.3.7
  if(version_is_less(version:cupsVer, test_version:"1.2.0") ||
     version_is_equal(version:cupsVer, test_version:"1.3.7")){
    security_hole(cupsPort);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_ipp_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# CUPS IPP Packets Processing Denial of Service Vulnerability
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
tag_impact = "An attacker can exploit will allow application to crash.
  Impact Level: Application";
tag_affected = "CUPS version prior to 1.3.10";
tag_insight = "The flaw is cause due to a NULL-pointer dereference that occurs when
  processing two consecutive IPP_TAG_UNSUPPORTED tags in specially
  crafted IPP (Internet Printing Protocol) packets.";
tag_solution = "Upgrade to version 1.3.10 or latest
  http://www.cups.org/software.php";
tag_summary = "This host is running CUPS, and is prone to Denial of Service
  Vulnerability.";

if(description)
{
  script_id(800581);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0949");
  script_bugtraq_id(35169);
  script_name("CUPS IPP Packets Processing Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/AppleCUPS-null-pointer-vulnerability");

  script_description(desc);
  script_summary("Check for the Version of CUPS");
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
  # Check for CUPS version < 1.3.10
  if(version_is_less(version:cupsVer, test_version:"1.3.10")){
    security_warning(cupsPort);
  }
}

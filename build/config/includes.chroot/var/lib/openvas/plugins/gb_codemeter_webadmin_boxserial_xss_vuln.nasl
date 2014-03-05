###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codemeter_webadmin_boxserial_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CodeMeter WebAdmin 'Licenses.html' Cross Site Scripting Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to execute arbitrary script
  code in the browser of an unsuspecting user in the context of the affected
  site.
  Impact Level: Application";
tag_affected = "CodeMeter WebAdmin version 4.30 and 3.30";
tag_insight = "The flaw is due to an input passed via the 'BoxSerial' parameter to the
  'Licenses.html' script is not properly sanitised before being returned
  to the user.";
tag_solution = "No solution or patch is available as of 3rd October, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://support.codemeter.de/en/index.html";
tag_summary = "The host is running CodeMeter WebAdmin and is prone to
  cross-site scripting vulnerability.";

if(description)
{
  script_id(801989);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-3689");
  script_bugtraq_id(48082);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("CodeMeter WebAdmin 'Licenses.html' Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/72811");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44800/");
  script_xref(name : "URL" , value : "http://forums.cnet.com/7726-6132_102-5144590.html");
  script_xref(name : "URL" , value : "http://www.solutionary.com/index/SERT/Vuln-Disclosures/CodeMeter-WebAdmin.html");

  script_description(desc);
  script_summary("Check for the version of CodeMeter WebAdmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH,");
  script_family("Web application abuses");
  script_dependencies("gb_codemeter_webadmin_detect.nasl");
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

## Default port
cwaPort= 22350;

##Check the port status
if(!get_port_state(cwaPort)){
  exit(0);
}

## Get the version from KB
cmwVer = get_kb_item("www/" + cwaPort + "/CodeMeter_WebAdmin");
if(cmwVer)
{
   ## Check for version before 4.30 and 3.30
   if(version_is_equal(version:cmwVer, test_version:"4.30") ||
      version_is_equal(version:cmwVer, test_version:"3.30")){
     security_warning(port);
   }
}

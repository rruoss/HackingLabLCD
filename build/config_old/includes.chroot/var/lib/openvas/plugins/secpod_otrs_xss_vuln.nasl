##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_otrs_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Open Ticket Request System (OTRS) 'AgentTicketZoom' Cross-site scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902352";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2010-4071");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-22 08:43:18 +0100 (Tue, 22 Mar 2011)");
  script_name("Open Ticket Request System (OTRS) 'AgentTicketZoom' Cross-site scripting Vulnerability");

tag_summary =
"This host is running Open Ticket Request System (OTRS) and is prone to
Cross-site scripting vulnerability.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"The flaw is due to input passed via HTML e-mails is not properly sanitised in
AgentTicketZoom before being displayed to the user.";

tag_impact =
"Successful exploitation will allow attackers to insert arbitrary HTML and
script code, which will be executed in a user's browser session in the
context of an affected site when malicious data is being viewed.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version 2.4.x before 2.4.9.";

tag_solution =
"Upgrade to Open Ticket Request System (OTRS) version 2.4.9 or later For updates
refer to http://otrs.org/download/";

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
  script_xref(name : "URL" , value : "http://osvdb.org/68882");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41978");
  script_xref(name : "URL" , value : "http://otrs.org/advisory/OSA-2010-03-en/");
  script_summary("Check for the version of Open Ticket Request System (OTRS)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP.

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
  if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.8"))
  {
    security_warning(port);
  }
}
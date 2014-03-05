###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_itsm_ticket_split_info_disclosure_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# OTRS ITSM Ticket Split Information Disclosure Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803942";
OTRSCPE = "cpe:/a:otrs:otrs";
ITSMCPE = "cpe:/a:otrs:otrs_itsm";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3551");
  script_bugtraq_id(60117);
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-27 15:32:31 +0530 (Fri, 27 Sep 2013)");
  script_name("OTRS ITSM Ticket Split Information Disclosure Vulnerability");

tag_summary =
"This host is installed with OTRS (Open Ticket Request System) or OTRS:ITSM
and is prone to information disclosure vulnerability.";

tag_vuldetect =
"Get the installed version and location of OTRS with the help of detect NVT
and check the OTRS and OTRS:ITSM version is vulnerable or not.";

tag_insight =
"An error exists in application when handling URLs related to the ticket split
mechanism";

tag_impact =
"Successful exploitation will allow remote attackers to gain access to
sensitive information.

Impact Level: Application";

tag_affected =
"OTRS (Open Ticket Request System) version 3.0.x up to and including 3.0.19,
3.1.x up to and including 3.1.15 and 3.2.x up to and including 3.2.6
OTRS::ITSM 3.1.0 up to and including 3.1.8, 3.0.0 up to and including 3.0.7
and 3.2.0 up to and including 3.2.4";

tag_solution =
"Upgrade to OTRS (Open Ticket Request System) version 3.0.20, 3.1.16 and 3.2.7
or later, and OTRS::ITSM version 3.2.5, 3.1.9 and 3.0.8 For updates refer to
http://www.otrs.com/en/ or Apply patch from the vendor advisory link
http://www.otrs.com/en/open-source/community-news/security-advisories/security-advisory-2013-03/";

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
  script_xref(name : "URL" , value : "http://osvdb.org/93628");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/60117");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53496/");
  script_xref(name : "URL" , value : "http://www.otrs.com/en/open-source/community-news/security-advisories/security-advisory-2013-03/");
  script_summary("Check for the vulnerable version of OTRS and OTRS::ITSM");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("secpod_otrs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0); # this nvt is prone to FP.

## Variable initialisation
port = "";
vers = "";
itsmvers = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:OTRSCPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get OTRS version
if(vers = get_app_version(cpe:OTRSCPE, nvt:SCRIPT_OID, port:port))
{
  if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.6") ||
     version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.19") ||
     version_in_range(version:vers, test_version:"3.1.0", test_version2:"3.1.15"))
  {
      security_warning(port:port);
      exit(0);
  }

}

## Get ITSM version
if(itsmvers = get_app_version(cpe:ITSMCPE, nvt:SCRIPT_OID, port:port))
{
  if(version_in_range(version:itsmvers, test_version:"3.1.0", test_version2:"3.1.8") ||
     version_in_range(version:itsmvers, test_version:"3.0.0", test_version2:"3.0.7") ||
     version_in_range(version:itsmvers, test_version:"3.2.0", test_version2:"3.2.4"))
  {
    security_warning(port:port);
    exit(0);
  }
}

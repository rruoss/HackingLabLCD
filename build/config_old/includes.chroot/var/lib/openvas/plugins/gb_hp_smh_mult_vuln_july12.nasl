##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_mult_vuln_july12.nasl 12 2013-10-27 11:15:33Z jan $
#
# HP System Management Homepage Multiple Vulnerabilities - July 2012
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to gain elevated privileges,
  disclose sensitive information, perform unauthorized actions, or cause
  denial of service conditions.
  Impact Level: System/Application";
tag_affected = "HP System Management Homepage (SMH) versions before 7.1.1";
tag_insight = "- An unspecified local security vulnerability
  - A denial of service vulnerability
  - An input validation vulnerability
  - A privilege escalation vulnerability
  - An information-disclosure vulnerability";
tag_solution = "Upgrade to HP System Management Homepage (SMH) version 7.1.1 or later,
  For updates refer to http://h18013.www1.hp.com/products/servers/management/agents/documentation.html";
tag_summary = "This host is running HP System Management Homepage (SMH) and is
  prone to multiple vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802657";
CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(54218);
  script_cve_id("CVE-2012-2012", "CVE-2012-2013", "CVE-2012-2014", "CVE-2012-2015",
                "CVE-2012-2016");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-09 15:15:15 +0530 (Mon, 09 Jul 2012)");
  script_name("HP System Management Homepage Multiple Vulnerabilities - July 2012");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49592");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027209");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/54218");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03360041");

  script_description(desc);
  script_summary("Check for the version of HP SMH");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_require_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2381);
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
include("host_details.inc");

## Variable Initialization
port = 0;
version = NULL;

## Get HP SMH Port
if(! port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get HP SMH Version
if(! version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)) {
  exit(0);
}

## Check for HP System Management Homepage versions before 7.1.1
if(version_is_less(version:version, test_version:"7.1.1")){
  security_hole(port);
}

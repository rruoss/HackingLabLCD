###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_1200_mult_dos_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Siemens SIMATIC S7-1200 Multiple Denial of Service Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_impact = "Successful exploitation will allow attackers to cause denial of service
  via specially-crafted packets to TCP port 102 or UCP port 161.
  Impact Level: Application";

tag_summary = "This host is installed with Siemens SIMATIC S7-1200 and is prone
  to multiple denial of service vulnerabilities.";
tag_solution = "No solution or patch is available as of 25th April, 2013. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.siemens.com/cert/advisories";
tag_insight = "Multiple flaws allows device management over TCP and UDP ports.";
tag_affected = "Siemens SIMATIC S7-1200 2.x and 3.x";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803387";
CPE = "cpe:/h:siemens:simatic_s7-1200_plc";

if (description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_oid(SCRIPT_OID);
  script_version ("$Revision: 11 $");
  script_cve_id("CVE-2013-0700","CVE-2013-2780");
  script_bugtraq_id(59399,57023);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-25 16:01:27 +0530 (Thu, 25 Apr 2013)");
  script_name("Siemens SIMATIC S7-1200 Multiple Denial of Service Vulnerabilities");
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

  script_description(desc);
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2013-0700");
  script_xref(name : "URL" , value : "http://cxsecurity.com/cveshow/CVE-2013-2780");
  script_xref(name : "URL" , value : "http://www.siemens.com/corporate-technology/pool/de/forschungsfelder/siemens_security_advisory_ssa-724606.pdf");
  script_summary("Check for vulnerable version of Siemens SIMATIC S7-1200");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_simatic_S7_1200_plc_detect.nasl");
  script_require_ports("Services/www", 80,"Services/snmp", 161);
  script_mandatory_keys("simatic_s7_1200/installed");
  exit(0);
}

include("host_details.inc");

## Variable Initialization
port = 0;
version = "";

## Get port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get version
if(!version = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Check for version 2.x or 3.x
if(version =~ "^(2\.|3\.)")
{
  security_hole(port:port);
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_colasoft_capsa_snmp_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Colasoft Capsa Malformed SNMP V1 Packet Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to crash the affected
  application, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "Colasoft Capsa Version 7.2.1 and prior.";
tag_insight = "The flaw is due to an unspecified error within the SNMPv1 protocol
  dissector and can be exploited to cause a crash via a specially crafted
  packet.";
tag_solution = "No solution or patch is available as of 22rd September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.colasoft.com/download/products/download_capsa.php";
tag_summary = "This host is installed with Colasoft Capsa and is prone to denial
  of service vulnerability.";

if(description)
{
  script_id(902570);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_bugtraq_id(49621);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Colasoft Capsa Malformed SNMP V1 Packet Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46034");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519630");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2011-09/0088.html");

  script_description(desc);
  script_summary("Check for the version of Colasoft Capsa");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Confirm Colasoft Capsa
key = "SOFTWARE\Colasoft\Colasoft Capsa 7 Enterprise Demo Edition";
if(!registry_key_exists(key:key)) {
  exit(0);
}

## Get Version From Registry
version = registry_get_sz(key:key, item:"Version");
if(version)
{
 ## Check for Colasoft Capsa Version 7.2.1 and prior
 if(version_is_less_equal(version:version, test_version:"7.2.1.2299")) {
    security_hole(0);
  }
}

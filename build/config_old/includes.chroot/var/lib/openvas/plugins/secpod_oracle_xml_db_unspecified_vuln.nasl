###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_xml_db_unspecified_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Oracle Database 'XML DB component' Unspecified vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_solution = "Apply patches from below link,
  http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuapr2010.html

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will let remote authenticated users to affect
  confidentiality via unknown vectors.
  Impact Level: Application";
tag_affected = "Oracle Database versions 9.2.0.8, 9.2.0.8DV, 10.1.0.5 and 10.2.0.3";
tag_insight = "The flaw is due to unspecified errors in the 'XML DB component',
  and unknown impact and attack vectors.";
tag_summary = "This host is running Oracle database and is prone to unspecified
  vulnerability.";

if(description)
{
  script_id(902043);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_cve_id("CVE-2010-0851");
  script_bugtraq_id(39434);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Oracle Database 'XML DB component' Unspecified vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/39438");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/392881.php");
  script_xref(name : "URL" , value : "http://www.us-cert.gov/cas/techalerts/TA10-103B.html");
  script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln39434.html");

  script_description(desc);
  script_summary("Check for the version of Oracle Database");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Databases");
  script_dependencies("oracle_tnslsnr_version.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

dbPort = "1521";
if(!get_port_state(dbPort)){
  exit(0);
}

dbVer = get_kb_item("oracle_tnslsnr/" + dbPort + "/version");
if(dbVer != NULL)
{
  dbVer = eregmatch(pattern:"Version (([0-9.]+).?([A-Za-z]+)?)", string:dbVer);
  if(dbVer[1] != NULL)
  {
    if(version_is_less(version:dbVer[1], test_version:"9.2.0.8DV") ||
       version_is_equal(version:dbVer[1], test_version:"10.1.0.5") ||
       version_is_equal(version:dbVer[1], test_version:"10.2.0.3")){
      security_warning(dbPort);
    }
  }
}

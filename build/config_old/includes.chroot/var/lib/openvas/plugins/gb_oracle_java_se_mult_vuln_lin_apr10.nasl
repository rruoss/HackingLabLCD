###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_vuln_lin_apr10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Oracle Java SE Multiple Vulnerabilities (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful attacks will allow attackers to affect confidentiality, integrity,
  and availability via unknown vectors.
  Impact Level: Application";
tag_affected = "Sun Java SE version 6 Update 18, 5.0 Update 23 on Linux.";
tag_insight = "Multiple flaws are due to memory corruptions, buffer overflows, input
  validation and implementation errors in following components,
   - HotSpot Server,
   - Java Runtime Environment,
   - Java Web Start,
   - Java Plug-in,
   - Java 2D,
   - Sound and
   - imageIO components";
tag_solution = "Upgrade to SE 6 Update 19, JDK and JRE 5.0 Update 24,
  http://www.oracle.com/technology/deploy/security/critical-patch-updates/javacpumar2010.html";
tag_summary = "This host is installed with Sun Java SE and is prone to multiple
  vulnerabilities.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800500";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-07 16:20:50 +0200 (Wed, 07 Apr 2010)");
  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085",
                "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090",
                "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094",
                "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839",
                "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843",
                "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847",
                "CVE-2010-0848", "CVE-2010-0849");
  script_bugtraq_id(36935, 39085, 39093, 39094, 39068, 39081, 39095, 39091, 39096,
                    39090, 39088, 39075, 39086, 39072, 39069, 39070, 39065, 39067,
                    39077, 39083, 39084, 39089, 39062, 39071, 39078, 39073);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Oracle Java SE Multiple Vulnerabilities (Linux)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0747");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Mar/1023774.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technology/deploy/security/critical-patch-updates/javacpumar2010.html");

  script_description(desc);
  script_summary("Check for the Version of Sun Java SE JRE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_require_keys("Sun/Java/JRE/Linux/Ver");
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

jreVer = get_app_version(cpe:"cpe:/a:sun:jre", nvt:SCRIPT_OID);

if(jreVer)
{
  jreVer = ereg_replace(pattern:"_", string:jreVer, replace: ".");
  jreVer = ereg_replace(pattern:"-b[0-9][0-9]", string:jreVer, replace:""); 

  # Check for 1.6 < 1.6.0_18 (6 Update 18), 1.5 < 1.6.0_23(6 Update 23)
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.18") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.23")){
     security_hole(0);
  }
}
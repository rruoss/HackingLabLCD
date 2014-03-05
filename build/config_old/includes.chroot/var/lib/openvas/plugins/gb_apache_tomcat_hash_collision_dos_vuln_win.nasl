###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_hash_collision_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache Tomcat Hash Collision Denial Of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_solution = "Apply patch or upgrade Apache Tomcat to 5.5.35, 6.0.35, 7.0.23 or later,
  For updates refer to http://tomcat.apache.org/

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to cause a denial
  of service via a specially crafted form sent in a HTTP POST request.
  Impact Level: Application.";
tag_affected = "Apache Tomcat version before 5.5.35, 6.x to 6.0.34 and 7.x to 7.0.22 on Windows.";
tag_insight = "The flaw is due to an error within a hash generation function when
  computing hash values for form parameter and updating a hash table. This can
  be exploited to cause a hash collision resulting in high CPU consumption via
  a specially crafted form sent in a HTTP POST request.";
tag_summary = "The host is running Apache Tomcat Server and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802378);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-4858");
  script_bugtraq_id(51200);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-12 13:35:57 +0530 (Thu, 12 Jan 2012)");
  script_name("Apache Tomcat Hash Collision Denial Of Service Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/903934");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=750521");
  script_xref(name : "URL" , value : "http://www.ocert.org/advisories/ocert-2011-003.html");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/tomcat-7.0-doc/changelog.html");

  script_description(desc);
  script_summary("Check for the version of Apache Tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect_win.nasl");
  script_require_keys("ApacheTomcat/Win/Ver");
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

## Get the version from KB
tomcatVer = get_kb_item("ApacheTomcat/Win/Ver");
if(!tomcatVer){
  exit(0);
}

# Check Tomcat version < 5.5.28, or < 6.0.20
if(version_is_less(version:tomcatVer, test_version:"5.5.35") ||
   version_in_range(version:tomcatVer, test_version:"6.0", test_version2:"6.0.34")||
   version_in_range(version:tomcatVer, test_version:"7.0", test_version2:"7.0.22")){
  security_warning(0);
}

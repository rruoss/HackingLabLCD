###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for phpldapadmin MDVSA-2011:163 (phpldapadmin)
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Multiple vulnerabilities was discovered and corrected in phpldapadmin:

  Input appended to the URL in cmd.php \(when cmd is set to _debug\)
  is not properly sanitised before being returned to the user. This can
  be exploited to execute arbitrary HTML and script code in a user&amp;#039;s
  browser session in context of an affected site (CVE-2011-4074).
  
  Input passed to the orderby parameter in cmd.php \(when cmd is set
  to query_engine, query is set to none, and search is set to e.g. 1\)
  is not properly sanitised in lib/functions.php before being used in
  a create_function() function call. This can be exploited to inject
  and execute arbitrary PHP code (CVE-2011-4075).
  
  The updated packages have been upgraded to the latest version (1.2.2)
  which is not vulnerable to these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "phpldapadmin on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-11/msg00001.php");
  script_id(831481);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVSA", value: "2011:163");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-4074", "CVE-2011-4075");
  script_name("Mandriva Update for phpldapadmin MDVSA-2011:163 (phpldapadmin)");

  script_description(desc);
  script_summary("Check for the Version of phpldapadmin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"phpldapadmin", rpm:"phpldapadmin~1.2.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

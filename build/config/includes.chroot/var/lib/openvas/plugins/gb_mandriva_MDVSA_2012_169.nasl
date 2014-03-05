###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for java-1.6.0-openjdk MDVSA-2012:169 (java-1.6.0-openjdk)
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Multiple security issues were identified and fixed in OpenJDK
  (icedtea6):

  * S6631398, CVE-2012-3216: FilePermission improved path checking
  * S7093490: adjust package access in rmiregistry
  * S7143535, CVE-2012-5068: ScriptEngine corrected permissions
  * S7167656, CVE-2012-5077: Multiple Seeders are being created
  * S7169884, CVE-2012-5073: LogManager checks do not work correctly
  for sub-types
  * S7169888, CVE-2012-5075: Narrowing resource definitions in JMX
  RMI connector
  * S7172522, CVE-2012-5072: Improve DomainCombiner checking
  * S7186286, CVE-2012-5081: TLS implementation to better adhere to RFC
  * S7189103, CVE-2012-5069: Executors needs to maintain state
  * S7189490: More improvements to DomainCombiner checking
  * S7189567, CVE-2012-5085: java net obselete protocol
  * S7192975, CVE-2012-5071: Conditional usage check is wrong
  * S7195194, CVE-2012-5084: Better data validation for Swing
  * S7195917, CVE-2012-5086: XMLDecoder parsing at close-time should
  be improved
  * S7195919, CVE-2012-5979: (sl) ServiceLoader can throw CCE without
  needing to create instance
  * S7198296, CVE-2012-5089: Refactor classloader usage
  * S7158800: Improve storage of symbol tables
  * S7158801: Improve VM CompileOnly option
  * S7158804: Improve config file parsing
  * S7176337: Additional changes needed for 7158801 fix
  * S7198606, CVE-2012-4416: Improve VM optimization

  The updated packages provides icedtea6-1.11.5 which is not vulnerable
  to these issues.";

tag_affected = "java-1.6.0-openjdk on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:169");
  script_id(831749);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"creation_date", value:"2012-11-02 11:02:07 +0530 (Fri, 02 Nov 2012)");
  script_cve_id("CVE-2012-3216", "CVE-2012-5068", "CVE-2012-5077", "CVE-2012-5073",
                "CVE-2012-5075", "CVE-2012-5072", "CVE-2012-5081", "CVE-2012-5069",
                "CVE-2012-5085", "CVE-2012-5071", "CVE-2012-5084", "CVE-2012-5086",
                "CVE-2012-5979", "CVE-2012-5089", "CVE-2012-4416");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2012:169");
  script_name("Mandriva Update for java-1.6.0-openjdk MDVSA-2012:169 (java-1.6.0-openjdk)");

  script_description(desc);
  script_summary("Check for the Version of java-1.6.0-openjdk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~35.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~35.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~35.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~35.b24.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~35.b24.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~35.b24.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~35.b24.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~35.b24.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
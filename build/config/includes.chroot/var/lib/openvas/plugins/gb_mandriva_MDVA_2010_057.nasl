###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for nuface MDVA-2010:057 (nuface)
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_affected = "nuface on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";
tag_insight = "Update to new version. Fix many bugs and add functionalities for
  nuface interface.";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-02/msg00015.php");
  script_id(830871);
  script_version("$Revision: 14 $");
  script_cve_id("CVE-2010-0434");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-15 16:07:49 +0100 (Mon, 15 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVA", value: "2010:057");
  script_name("Mandriva Update for nuface MDVA-2010:057 (nuface)");

  script_description(desc);
  script_summary("Check for the Version of nuface");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libnuclient3", rpm:"libnuclient3~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libnufw-devel", rpm:"libnufw-devel~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nuface", rpm:"nuface~2.0.14~3.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw", rpm:"nufw~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw-nuauth", rpm:"nufw-nuauth~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw-nuauth-auth-ldap", rpm:"nufw-nuauth-auth-ldap~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw-nuauth-log-mysql", rpm:"nufw-nuauth-log-mysql~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw-nuauth-log-pgsql", rpm:"nufw-nuauth-log-pgsql~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw-nuauth-log-prelude", rpm:"nufw-nuauth-log-prelude~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw-nutcpc", rpm:"nufw-nutcpc~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nufw-utils", rpm:"nufw-utils~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_nufw", rpm:"pam_nufw~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-nufw", rpm:"python-nufw~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squid_nufw_helper", rpm:"squid_nufw_helper~1.0.0~0.rc2.5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64nuclient3", rpm:"lib64nuclient3~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64nufw-devel", rpm:"lib64nufw-devel~2.2.21~5.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

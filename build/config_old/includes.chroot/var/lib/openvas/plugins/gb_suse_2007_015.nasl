###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for AppArmor SUSE-SA:2007:015
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Two new language features have been added to improve the
  confinement provided to applications executing other applications will
  confined by AppArmor.

  - Two new execute modifiers: 'P' and 'U' are provided and are flavors
  of the existing 'p' and 'u' modifiers but indicate that the
  environment should be stripped across the execute transition.

  Using &quot;Ux&quot; and &quot;Px&quot; avoids injecting code using LD_PRELOAD and
  similar variables into the started executables by a infected
  profiled program.

  The environment variable filtering is the same as used for setuid
  applications.

  - A new permission 'm' is required when an application executes
  mmap(2) with protection PROT_EXEC.

  This avoids infected binaries escalating the &quot;r&quot; privilege to a
  file into a &quot;rx&quot; privilege.

  Note that both issues are not directly security fixes, they instead
  avoid common problems during profile creation.

  These changes also require a new kernel, which we released in December
  2006, tracked by our advisory SUSE-SA:2006:079.

  Only SUSE Linux Enterprise Server 9 (and related products) and SUSE
  Linux 10.0 are affected by this change. SUSE Linux 10.1, SUSE Linux
  Enterprise 10 and newer products already contain the new profile
  syntax and behavior.";

tag_impact = "AppArmor language additions";
tag_affected = "AppArmor on SUSE SLES 9, Novell Linux Desktop 9, Open Enterprise Server, Novell Linux POS 9";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_15_apparmor.html");
  script_id(850096);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "SUSE-SA", value: "2007-015");
  script_name( "SuSE Update for AppArmor SUSE-SA:2007:015");

  script_description(desc);
  script_summary("Check for the Version of AppArmor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
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

if(release == "OES")
{

  if ((res = isrpmvuln(pkg:"subdomain-parser", rpm:"subdomain-parser~1.2~42_imnx_suse", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-parser-common", rpm:"subdomain-parser-common~1.2~42_imnx_suse", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-profiles", rpm:"subdomain-profiles~1.2_SLES9~21_imnx_suse", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-utils", rpm:"subdomain-utils~1.2~23_imnx_suse", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-subdomain", rpm:"yast2-subdomain~1.2~11.1_imnx", rls:"OES")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLES9")
{

  if ((res = isrpmvuln(pkg:"subdomain-parser", rpm:"subdomain-parser~1.2~42_imnx_suse", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-parser-common", rpm:"subdomain-parser-common~1.2~42_imnx_suse", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-profiles", rpm:"subdomain-profiles~1.2_SLES9~21_imnx_suse", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-utils", rpm:"subdomain-utils~1.2~23_imnx_suse", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-subdomain", rpm:"yast2-subdomain~1.2~11.1_imnx", rls:"SLES9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"subdomain-parser", rpm:"subdomain-parser~1.2~42_imnx_suse", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-parser-common", rpm:"subdomain-parser-common~1.2~42_imnx_suse", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-profiles", rpm:"subdomain-profiles~1.2_SLES9~21_imnx_suse", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-utils", rpm:"subdomain-utils~1.2~23_imnx_suse", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-subdomain", rpm:"yast2-subdomain~1.2~11.1_imnx", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLPOS9")
{

  if ((res = isrpmvuln(pkg:"subdomain-parser", rpm:"subdomain-parser~1.2~42_imnx_suse", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-parser-common", rpm:"subdomain-parser-common~1.2~42_imnx_suse", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-profiles", rpm:"subdomain-profiles~1.2_SLES9~21_imnx_suse", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subdomain-utils", rpm:"subdomain-utils~1.2~23_imnx_suse", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"yast2-subdomain", rpm:"yast2-subdomain~1.2~11.1_imnx", rls:"NLPOS9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for bind SUSE-SA:2011:029
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
tag_insight = "A remote Denial of Service vulnerability has been fixed in the BIND
  DNS nameserver.

  Specially crafted packets could cause bind servers (recursive as well
  as authoritative) to exit. CVE-2011-2464

  This issue affected bind 9.6 and later, so SUSE Linux Enterprise
  10 SP4, SUSE Linux Enterprise 11 SP1 and openSUSE 11.3 and 11.4
  were affected.

  Older service packs / products are not affected by CVE-2011-2464.


  Please also note that the other currently published security issue,
  CVE-2011-2465, affected only BIND versions 9.8.0 and later, which none
  of our current products include, making all of them not affected by
  this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "remote denial of service";
tag_affected = "bind on openSUSE 11.3, openSUSE 11.4";

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
  script_xref(name : "URL" , value : "http://www.suse.com/support/security/advisories/2011_29_bind.html");
  script_id(850168);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "SUSE-SA", value: "2011-029");
  script_cve_id("CVE-2011-2464", "CVE-2011-2465");
  script_name("SuSE Update for bind SUSE-SA:2011:029");

  script_description(desc);
  script_summary("Check for the Version of bind");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
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

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.7.3P3~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.7.3P3~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.7.3P3~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.7.3P3~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.7.3P3~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.7.3P3~0.2.1", rls:"openSUSE11.4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.7.3P3~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.7.3P3~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.7.3P3~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.7.3P3~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.7.3P3~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.7.3P3~0.2.1", rls:"openSUSE11.3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

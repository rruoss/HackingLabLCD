###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for gd MDKSA-2007:122 (gd)
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
tag_insight = "A flaw in libgd2 was found by Xavier Roche where it would not correctly
  validate PNG callback results.  If an application linked against
  libgd2 was tricked into processing a specially-crafted PNG file, it
  could cause a denial of service scenario via CPU resource consumption.

  The updated packages have been patched to prevent this issue.";

tag_affected = "gd on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-06/msg00013.php");
  script_id(830177);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:57:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDKSA", value: "2007:122");
  script_cve_id("CVE-2007-2756");
  script_name( "Mandriva Update for gd MDKSA-2007:122 (gd)");

  script_description(desc);
  script_summary("Check for the Version of gd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-devel", rpm:"libgd2-devel~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-static-devel", rpm:"libgd2-static-devel~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-devel", rpm:"lib64gd2-devel~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-static-devel", rpm:"lib64gd2-static-devel~2.0.34~1.1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2", rpm:"libgd2~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-devel", rpm:"libgd2-devel~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgd2-static-devel", rpm:"libgd2-static-devel~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gd", rpm:"gd~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2", rpm:"lib64gd2~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-devel", rpm:"lib64gd2-devel~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gd2-static-devel", rpm:"lib64gd2-static-devel~2.0.33~5.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

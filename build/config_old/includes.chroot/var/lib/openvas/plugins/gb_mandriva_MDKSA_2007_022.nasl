###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for tetex MDKSA-2007:022 (tetex)
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
tag_insight = "The Adobe PDF specification 1.3, as implemented by xpdf 3.0.1 patch 2,
  kpdf in KDE before 3.5.5, and other products, allows remote attackers
  to have an unknown impact, possibly including denial of service
  (infinite loop), arbitrary code execution, or memory corruption, via a
  PDF file with a (1) crafted catalog dictionary or (2) a crafted Pages
  attribute that references an invalid page tree node.

  The updated packages have been patched to correct this problem.";

tag_affected = "tetex on Mandriva Linux 2006.0,
  Mandriva Linux 2006.0/X86_64,
  Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-01/msg00032.php");
  script_id(830054);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDKSA", value: "2007:022");
  script_cve_id("CVE-2007-0104");
  script_name( "Mandriva Update for tetex MDKSA-2007:022 (tetex)");

  script_description(desc);
  script_summary("Check for the Version of tetex");
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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"jadetex", rpm:"jadetex~3.12~116.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex", rpm:"tetex~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-afm", rpm:"tetex-afm~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-context", rpm:"tetex-context~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-devel", rpm:"tetex-devel~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-doc", rpm:"tetex-doc~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvilj", rpm:"tetex-dvilj~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvipdfm", rpm:"tetex-dvipdfm~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvips", rpm:"tetex-dvips~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-latex", rpm:"tetex-latex~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-mfwin", rpm:"tetex-mfwin~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-texi2html", rpm:"tetex-texi2html~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-xdvi", rpm:"tetex-xdvi~3.0~18.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmltex", rpm:"xmltex~1.9~64.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2006.0")
{

  if ((res = isrpmvuln(pkg:"jadetex", rpm:"jadetex~3.12~110.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex", rpm:"tetex~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-afm", rpm:"tetex-afm~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-context", rpm:"tetex-context~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-devel", rpm:"tetex-devel~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-doc", rpm:"tetex-doc~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvilj", rpm:"tetex-dvilj~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvipdfm", rpm:"tetex-dvipdfm~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-dvips", rpm:"tetex-dvips~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-latex", rpm:"tetex-latex~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-mfwin", rpm:"tetex-mfwin~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-texi2html", rpm:"tetex-texi2html~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tetex-xdvi", rpm:"tetex-xdvi~3.0~12.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xmltex", rpm:"xmltex~1.9~58.3.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
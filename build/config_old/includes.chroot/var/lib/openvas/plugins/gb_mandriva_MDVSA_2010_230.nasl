###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for poppler MDVSA-2010:230 (poppler)
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
tag_insight = "Multiple vulnerabilities were discovered and corrected in poppler:

  The Gfx::getPos function in the PDF parser in poppler, allows
  context-dependent attackers to cause a denial of service (crash)
  via unknown vectors that trigger an uninitialized pointer dereference
  (CVE-2010-3702).
  
  The FoFiType1::parse function in fofi/FoFiType1.cc in the PDF parser
  in poppler, allows context-dependent attackers to cause a denial
  of service (crash) and possibly execute arbitrary code via a PDF
  file with a crafted Type1 font that contains a negative array index,
  which bypasses input validation and which triggers memory corruption
  (CVE-2010-3704).
  
  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=490
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "poppler on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Enterprise Server 5,
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-11/msg00023.php");
  script_id(831249);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVSA", value: "2010:230");
  script_cve_id("CVE-2010-3702", "CVE-2010-3704");
  script_name("Mandriva Update for poppler MDVSA-2010:230 (poppler)");

  script_description(desc);
  script_summary("Check for the Version of poppler");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
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

  if ((res = isrpmvuln(pkg:"libpoppler3", rpm:"libpoppler3~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib3", rpm:"libpoppler-glib3~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt2", rpm:"libpoppler-qt2~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-3", rpm:"libpoppler-qt4-3~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt-devel", rpm:"libpoppler-qt-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler3", rpm:"lib64poppler3~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib3", rpm:"lib64poppler-glib3~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt2", rpm:"lib64poppler-qt2~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-3", rpm:"lib64poppler-qt4-3~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-devel", rpm:"lib64poppler-qt4-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt-devel", rpm:"lib64poppler-qt-devel~0.8.7~2.4mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"libpoppler3", rpm:"libpoppler3~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-devel", rpm:"libpoppler-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib3", rpm:"libpoppler-glib3~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-glib-devel", rpm:"libpoppler-glib-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt2", rpm:"libpoppler-qt2~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-3", rpm:"libpoppler-qt4-3~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt4-devel", rpm:"libpoppler-qt4-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpoppler-qt-devel", rpm:"libpoppler-qt-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler3", rpm:"lib64poppler3~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-devel", rpm:"lib64poppler-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib3", rpm:"lib64poppler-glib3~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-glib-devel", rpm:"lib64poppler-glib-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt2", rpm:"lib64poppler-qt2~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-3", rpm:"lib64poppler-qt4-3~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt4-devel", rpm:"lib64poppler-qt4-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64poppler-qt-devel", rpm:"lib64poppler-qt-devel~0.8.7~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openoffice.org MDVSA-2010:091 (openoffice.org)
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
tag_insight = "This updates provides a new OpenOffice.org version 3.1.1. It holds
  security and bug fixes described as follow:

  An integer underflow might allow remote attackers to execute arbitrary
  code via crafted records in the document table of a Word document,
  leading to a heap-based buffer overflow (CVE-2009-0200).
  
  A heap-based buffer overflow might allow remote attackers to execute
  arbitrary code via unspecified records in a crafted Word document,
  related to table parsing (CVE-2009-0201).
  
  A heap-based buffer overflow allows remote attackers to execute
  arbitrary code via a crafted EMF file (CVE-2009-2139).
  
  Multiple heap-based buffer overflows allow remote attackers to execute
  arbitrary code via a crafted EMF+ file (CVE-2009-2140).
  
  OpenOffice's xmlsec uses a bundled Libtool which might load .la
  file in the current working directory allowing local users to gain
  privileges via a Trojan horse file. For enabling such vulnerability
  xmlsec has to use --enable-crypto_dl building flag however it does
  not, although the fix keeps protected against this threat whenever
  that flag had been enabled (CVE-2009-3736).
  
  Addittionaly this update provides following bug fixes:
  
  OpenOffice.org is not properly configure to use the xdg-email
  functionality of the FreeDesktop standard (#52195).
  
  Template desktop icons are not properly set up then they are not
  presented under the context menu of applications like Dolphin (#56439).
  
  libia_ora-gnome is added as suggest as long as that package is needed
  for a better look (#57385#c28).
  
  It is enabled a fallback logic to properly select an OpenOffice.org
  style whenever one is set up but that is not installed (#57530#c1,
  #53284, #45133, #39043)
  
  It is enabled the Firefox plugin for viewing OpenOffice.org documents
  inside browser.
  
  Further packages were provided to supply OpenOffice.org. 3.1.1
  dependencies.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "openoffice.org on Mandriva Enterprise Server 5,
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-05/msg00004.php");
  script_id(831026);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-07 15:42:01 +0200 (Fri, 07 May 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2010:091");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201", "CVE-2009-2139", "CVE-2009-2140", "CVE-2009-3736");
  script_name("Mandriva Update for openoffice.org MDVSA-2010:091 (openoffice.org)");

  script_description(desc);
  script_summary("Check for the Version of openoffice.org");
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

  if ((res = isrpmvuln(pkg:"gnome-vfsmm2.6-doc", rpm:"gnome-vfsmm2.6-doc~2.24.0~1.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icu", rpm:"icu~4.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icu-doc", rpm:"icu-doc~4.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libglitz1", rpm:"libglitz1~0.5.6~3.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libglitz-devel", rpm:"libglitz-devel~0.5.6~3.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libglitz-static-devel", rpm:"libglitz-static-devel~0.5.6~3.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnome-vfsmm2.6_1", rpm:"libgnome-vfsmm2.6_1~2.24.0~1.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgnome-vfsmm2.6-devel", rpm:"libgnome-vfsmm2.6-devel~2.24.0~1.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libicu40", rpm:"libicu40~4.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libicu-devel", rpm:"libicu-devel~4.0~2.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvigra2", rpm:"libvigra2~1.5.0~3.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvigra-devel", rpm:"libvigra-devel~1.5.0~3.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-base", rpm:"openoffice.org-base~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-calc", rpm:"openoffice.org-calc~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-common", rpm:"openoffice.org-common~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-core", rpm:"openoffice.org-core~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-devel", rpm:"openoffice.org-devel~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-devel-doc", rpm:"openoffice.org-devel-doc~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-draw", rpm:"openoffice.org-draw~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-filter-binfilter", rpm:"openoffice.org-filter-binfilter~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-gnome", rpm:"openoffice.org-gnome~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-af", rpm:"openoffice.org-help-af~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ar", rpm:"openoffice.org-help-ar~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-bg", rpm:"openoffice.org-help-bg~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-br", rpm:"openoffice.org-help-br~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-bs", rpm:"openoffice.org-help-bs~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ca", rpm:"openoffice.org-help-ca~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-cs", rpm:"openoffice.org-help-cs~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-cy", rpm:"openoffice.org-help-cy~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-da", rpm:"openoffice.org-help-da~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-de", rpm:"openoffice.org-help-de~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-el", rpm:"openoffice.org-help-el~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-en_GB", rpm:"openoffice.org-help-en_GB~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-en_US", rpm:"openoffice.org-help-en_US~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-es", rpm:"openoffice.org-help-es~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-et", rpm:"openoffice.org-help-et~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-eu", rpm:"openoffice.org-help-eu~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-fi", rpm:"openoffice.org-help-fi~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-fr", rpm:"openoffice.org-help-fr~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-he", rpm:"openoffice.org-help-he~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-hi", rpm:"openoffice.org-help-hi~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-hu", rpm:"openoffice.org-help-hu~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-it", rpm:"openoffice.org-help-it~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ja", rpm:"openoffice.org-help-ja~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ko", rpm:"openoffice.org-help-ko~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-mk", rpm:"openoffice.org-help-mk~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nb", rpm:"openoffice.org-help-nb~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nl", rpm:"openoffice.org-help-nl~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-nn", rpm:"openoffice.org-help-nn~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pl", rpm:"openoffice.org-help-pl~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pt", rpm:"openoffice.org-help-pt~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-pt_BR", rpm:"openoffice.org-help-pt_BR~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ru", rpm:"openoffice.org-help-ru~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sk", rpm:"openoffice.org-help-sk~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sl", rpm:"openoffice.org-help-sl~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-sv", rpm:"openoffice.org-help-sv~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-ta", rpm:"openoffice.org-help-ta~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-tr", rpm:"openoffice.org-help-tr~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_CN", rpm:"openoffice.org-help-zh_CN~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zh_TW", rpm:"openoffice.org-help-zh_TW~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-help-zu", rpm:"openoffice.org-help-zu~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-impress", rpm:"openoffice.org-impress~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-java-common", rpm:"openoffice.org-java-common~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-af", rpm:"openoffice.org-l10n-af~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ar", rpm:"openoffice.org-l10n-ar~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bg", rpm:"openoffice.org-l10n-bg~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-br", rpm:"openoffice.org-l10n-br~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-bs", rpm:"openoffice.org-l10n-bs~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ca", rpm:"openoffice.org-l10n-ca~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cs", rpm:"openoffice.org-l10n-cs~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-cy", rpm:"openoffice.org-l10n-cy~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-da", rpm:"openoffice.org-l10n-da~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-de", rpm:"openoffice.org-l10n-de~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-el", rpm:"openoffice.org-l10n-el~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-en_GB", rpm:"openoffice.org-l10n-en_GB~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-es", rpm:"openoffice.org-l10n-es~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-et", rpm:"openoffice.org-l10n-et~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-eu", rpm:"openoffice.org-l10n-eu~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fi", rpm:"openoffice.org-l10n-fi~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-fr", rpm:"openoffice.org-l10n-fr~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-he", rpm:"openoffice.org-l10n-he~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hi", rpm:"openoffice.org-l10n-hi~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-hu", rpm:"openoffice.org-l10n-hu~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-it", rpm:"openoffice.org-l10n-it~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ja", rpm:"openoffice.org-l10n-ja~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ko", rpm:"openoffice.org-l10n-ko~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-mk", rpm:"openoffice.org-l10n-mk~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nb", rpm:"openoffice.org-l10n-nb~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nl", rpm:"openoffice.org-l10n-nl~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-nn", rpm:"openoffice.org-l10n-nn~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pl", rpm:"openoffice.org-l10n-pl~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt", rpm:"openoffice.org-l10n-pt~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-pt_BR", rpm:"openoffice.org-l10n-pt_BR~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ru", rpm:"openoffice.org-l10n-ru~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sk", rpm:"openoffice.org-l10n-sk~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sl", rpm:"openoffice.org-l10n-sl~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-sv", rpm:"openoffice.org-l10n-sv~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-ta", rpm:"openoffice.org-l10n-ta~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-tr", rpm:"openoffice.org-l10n-tr~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_CN", rpm:"openoffice.org-l10n-zh_CN~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zh_TW", rpm:"openoffice.org-l10n-zh_TW~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-l10n-zu", rpm:"openoffice.org-l10n-zu~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-math", rpm:"openoffice.org-math~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-mono", rpm:"openoffice.org-mono~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-openclipart", rpm:"openoffice.org-openclipart~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pdfimport", rpm:"openoffice.org-pdfimport~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-presentation-minimizer", rpm:"openoffice.org-presentation-minimizer~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-presenter-screen", rpm:"openoffice.org-presenter-screen~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-pyuno", rpm:"openoffice.org-pyuno~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-crystal", rpm:"openoffice.org-style-crystal~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-galaxy", rpm:"openoffice.org-style-galaxy~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-hicontrast", rpm:"openoffice.org-style-hicontrast~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-industrial", rpm:"openoffice.org-style-industrial~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-style-tango", rpm:"openoffice.org-style-tango~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-testtool", rpm:"openoffice.org-testtool~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-wiki-publisher", rpm:"openoffice.org-wiki-publisher~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-writer", rpm:"openoffice.org-writer~3.1.1~0.5mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glitz", rpm:"glitz~0.5.6~3.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-vfsmm2.6", rpm:"gnome-vfsmm2.6~2.24.0~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vigra", rpm:"vigra~1.5.0~3.1mdvmes5", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnome-vfsmm2.6-doc", rpm:"gnome-vfsmm2.6-doc~2.24.0~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icu", rpm:"icu~4.0~2.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icu-doc", rpm:"icu-doc~4.0~2.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64glitz1", rpm:"lib64glitz1~0.5.6~3.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64glitz-devel", rpm:"lib64glitz-devel~0.5.6~3.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64glitz-static-devel", rpm:"lib64glitz-static-devel~0.5.6~3.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gnome-vfsmm2.6_1", rpm:"lib64gnome-vfsmm2.6_1~2.24.0~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gnome-vfsmm2.6-devel", rpm:"lib64gnome-vfsmm2.6-devel~2.24.0~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64icu40", rpm:"lib64icu40~4.0~2.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64icu-devel", rpm:"lib64icu-devel~4.0~2.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64vigra2", rpm:"lib64vigra2~1.5.0~3.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64vigra-devel", rpm:"lib64vigra-devel~1.5.0~3.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kdegraphics MDVSA-2010:182 (kdegraphics)
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
tag_insight = "A vulnerability has been found and corrected in kdegraphics (ksvg):

  Use-after-free vulnerability in the garbage-collection implementation
  in WebCore in WebKit in Apple Safari before 4.0 allows remote
  attackers to execute arbitrary code or cause a denial of service
  (heap corruption and application crash) via an SVG animation element,
  related to SVG set objects, SVG marker elements, the targetElement
  attribute, and unspecified caches. (CVE-2009-1709)
  
  Packages for 2008.0 are provided as of the Extended Maintenance
  Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=490
  
  The updated packages have been patched to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "kdegraphics on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-09/msg00018.php");
  script_id(831156);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-22 08:32:53 +0200 (Wed, 22 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2010:182");
  script_cve_id("CVE-2009-1709");
  script_name("Mandriva Update for kdegraphics MDVSA-2010:182 (kdegraphics)");

  script_description(desc);
  script_summary("Check for the Version of kdegraphics");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-common", rpm:"kdegraphics-common~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kcolorchooser", rpm:"kdegraphics-kcolorchooser~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kcoloredit", rpm:"kdegraphics-kcoloredit~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kdvi", rpm:"kdegraphics-kdvi~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kfax", rpm:"kdegraphics-kfax~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kghostview", rpm:"kdegraphics-kghostview~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kiconedit", rpm:"kdegraphics-kiconedit~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kolourpaint", rpm:"kdegraphics-kolourpaint~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kooka", rpm:"kdegraphics-kooka~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kpdf", rpm:"kdegraphics-kpdf~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kpovmodeler", rpm:"kdegraphics-kpovmodeler~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kruler", rpm:"kdegraphics-kruler~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-ksnapshot", rpm:"kdegraphics-ksnapshot~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-ksvg", rpm:"kdegraphics-ksvg~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kuickshow", rpm:"kdegraphics-kuickshow~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-kview", rpm:"kdegraphics-kview~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kdegraphics-mrmlsearch", rpm:"kdegraphics-mrmlsearch~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-common", rpm:"libkdegraphics0-common~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-common-devel", rpm:"libkdegraphics0-common-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview", rpm:"libkdegraphics0-kghostview~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kghostview-devel", rpm:"libkdegraphics0-kghostview-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka", rpm:"libkdegraphics0-kooka~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kooka-devel", rpm:"libkdegraphics0-kooka-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler", rpm:"libkdegraphics0-kpovmodeler~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kpovmodeler-devel", rpm:"libkdegraphics0-kpovmodeler-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg", rpm:"libkdegraphics0-ksvg~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-ksvg-devel", rpm:"libkdegraphics0-ksvg-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kview", rpm:"libkdegraphics0-kview~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkdegraphics0-kview-devel", rpm:"libkdegraphics0-kview-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common", rpm:"lib64kdegraphics0-common~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-common-devel", rpm:"lib64kdegraphics0-common-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview", rpm:"lib64kdegraphics0-kghostview~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kghostview-devel", rpm:"lib64kdegraphics0-kghostview-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka", rpm:"lib64kdegraphics0-kooka~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kooka-devel", rpm:"lib64kdegraphics0-kooka-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler", rpm:"lib64kdegraphics0-kpovmodeler~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kpovmodeler-devel", rpm:"lib64kdegraphics0-kpovmodeler-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg", rpm:"lib64kdegraphics0-ksvg~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-ksvg-devel", rpm:"lib64kdegraphics0-ksvg-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview", rpm:"lib64kdegraphics0-kview~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64kdegraphics0-kview-devel", rpm:"lib64kdegraphics0-kview-devel~3.5.10~0.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

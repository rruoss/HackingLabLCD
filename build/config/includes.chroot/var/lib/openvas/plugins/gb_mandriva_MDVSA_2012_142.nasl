###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for gimp MDVSA-2012:142 (gimp)
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
tag_insight = "Multiple vulnerabilities has been discovered and corrected in gimp:

  A heap-based buffer overflow flaw, leading to invalid free, was
  found in the way KISS CEL file format plug-in of Gimp, the GNU Image
  Manipulation Program, performed loading of certain palette files. A
  remote attacker could provide a specially-crafted KISS palette file
  that, when opened in Gimp would cause the CEL plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running the gimp executable (CVE-2012-3403).

  Integer overflow, leading to heap-based buffer overflow flaw was
  found in the GIMP&#039;s GIF (Graphics Interchange Format) image file
  plug-in. An attacker could create a specially-crafted GIF image
  file that, when opened, could cause the GIF plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user
  running the GIMP (CVE-2012-3481).

  The updated gimp packages have been upgraded to the 2.6.12 version
  and patched to correct these issues.

  Additionally for Mandriva Enterprise server 5 the gegl packages
  was upgraded to the 0.0.22 version and rebuilt for ffmpeg 0.5.9,
  the enscript packages was added because of a build dependency, the
  gutenprint and mtink packages was rebuilt against the gimp 2.6.12
  libraries.";

tag_affected = "gimp on Mandriva Linux 2011.0,
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
  script_xref(name : "URL" , value : "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:142");
  script_id(831726);
  script_version("$Revision: 12 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"creation_date", value:"2012-08-24 09:57:21 +0530 (Fri, 24 Aug 2012)");
  script_cve_id("CVE-2012-3403", "CVE-2012-3481");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVSA", value: "2012:142");
  script_name("Mandriva Update for gimp MDVSA-2012:142 (gimp)");

  script_description(desc);
  script_summary("Check for the Version of gimp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "ssh/login/release");
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

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-python", rpm:"gimp-python~2.6.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0_0", rpm:"libgimp2.0_0~2.6.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0-devel", rpm:"libgimp2.0-devel~2.6.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0_0", rpm:"lib64gimp2.0_0~2.6.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0-devel", rpm:"lib64gimp2.0-devel~2.6.12~0.1", rls:"MNDK_2011.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"enscript", rpm:"enscript~1.6.4~8.2mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gegl", rpm:"gegl~0.0.22~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.12~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-python", rpm:"gimp-python~2.6.12~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gutenprint-common", rpm:"gutenprint-common~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gutenprint-cups", rpm:"gutenprint-cups~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gutenprint-escputil", rpm:"gutenprint-escputil~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gutenprint-foomatic", rpm:"gutenprint-foomatic~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gutenprint-gimp2", rpm:"gutenprint-gimp2~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gutenprint-ijs", rpm:"gutenprint-ijs~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgegl0", rpm:"libgegl0~0.0.22~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgegl-devel", rpm:"libgegl-devel~0.0.22~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0_0", rpm:"libgimp2.0_0~2.6.12~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0-devel", rpm:"libgimp2.0-devel~2.6.12~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgutenprint2", rpm:"libgutenprint2~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgutenprint2-devel", rpm:"libgutenprint2-devel~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgutenprintui2_1", rpm:"libgutenprintui2_1~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgutenprintui2_1-devel", rpm:"libgutenprintui2_1-devel~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mtink", rpm:"mtink~1.0.14~14.2mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gutenprint", rpm:"gutenprint~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gegl0", rpm:"lib64gegl0~0.0.22~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gegl-devel", rpm:"lib64gegl-devel~0.0.22~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0_0", rpm:"lib64gimp2.0_0~2.6.12~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0-devel", rpm:"lib64gimp2.0-devel~2.6.12~0.1mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gutenprint2", rpm:"lib64gutenprint2~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gutenprint2-devel", rpm:"lib64gutenprint2-devel~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gutenprintui2_1", rpm:"lib64gutenprintui2_1~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gutenprintui2_1-devel", rpm:"lib64gutenprintui2_1-devel~5.2.3~0.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
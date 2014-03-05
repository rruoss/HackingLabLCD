###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for gimp MDVSA-2011:103 (gimp)
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
tag_insight = "Multiple vulnerabilities was discovered and fixed in gimp:

  Stack-based buffer overflow in the &amp;quot;LIGHTING EFFECTS &amp;gt; LIGHT&amp;quot; plugin in
  GIMP 2.6.11 allows user-assisted remote attackers to cause a denial
  of service (application crash) or possibly execute arbitrary code
  via a long Position field in a plugin configuration file.  NOTE:
  it may be uncommon to obtain a GIMP plugin configuration file from
  an untrusted source that is separate from the distribution of the
  plugin itself (CVE-2010-4540).
  
  Stack-based buffer overflow in the SPHERE DESIGNER plugin in GIMP
  2.6.11 allows user-assisted remote attackers to cause a denial of
  service (application crash) or possibly execute arbitrary code via a
  long Number of lights field in a plugin configuration file.  NOTE:
  it may be uncommon to obtain a GIMP plugin configuration file from
  an untrusted source that is separate from the distribution of the
  plugin itself (CVE-2010-4541).
  
  Stack-based buffer overflow in the GFIG plugin in GIMP 2.6.11
  allows user-assisted remote attackers to cause a denial of service
  (application crash) or possibly execute arbitrary code via a long
  Foreground field in a plugin configuration file.  NOTE: it may be
  uncommon to obtain a GIMP plugin configuration file from an untrusted
  source that is separate from the distribution of the plugin itself
  (CVE-2010-4542).
  
  Heap-based buffer overflow in the read_channel_data function in
  file-psp.c in the Paint Shop Pro (PSP) plugin in GIMP 2.6.11 allows
  remote attackers to cause a denial of service (application crash)
  or possibly execute arbitrary code via a PSP_COMP_RLE (aka RLE
  compression) image file that begins a long run count at the end of
  the image (CVE-2010-4543, CVE-2011-1782).
  
  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. Please visit this link to learn more:
  http://store.mandriva.com/product_info.php\?cPath=149\&amp;amp;products_id=490
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "gimp on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-05/msg00029.php");
  script_id(831412);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-03 09:20:26 +0200 (Fri, 03 Jun 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2011:103");
  script_cve_id("CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542", "CVE-2010-4543", "CVE-2011-1782");
  script_name("Mandriva Update for gimp MDVSA-2011:103 (gimp)");

  script_description(desc);
  script_summary("Check for the Version of gimp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.4.7~1.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-python", rpm:"gimp-python~2.4.7~1.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0_0", rpm:"libgimp2.0_0~2.4.7~1.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0-devel", rpm:"libgimp2.0-devel~2.4.7~1.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0_0", rpm:"lib64gimp2.0_0~2.4.7~1.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0-devel", rpm:"lib64gimp2.0-devel~2.4.7~1.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.6.8~3.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-python", rpm:"gimp-python~2.6.8~3.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0_0", rpm:"libgimp2.0_0~2.6.8~3.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0-devel", rpm:"libgimp2.0-devel~2.6.8~3.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0_0", rpm:"lib64gimp2.0_0~2.6.8~3.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0-devel", rpm:"lib64gimp2.0-devel~2.6.8~3.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.4.7~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-python", rpm:"gimp-python~2.4.7~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0_0", rpm:"libgimp2.0_0~2.4.7~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgimp2.0-devel", rpm:"libgimp2.0-devel~2.4.7~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0_0", rpm:"lib64gimp2.0_0~2.4.7~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gimp2.0-devel", rpm:"lib64gimp2.0-devel~2.4.7~1.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
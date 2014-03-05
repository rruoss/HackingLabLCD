###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDVSA-2008:113 (kernel)
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
tag_insight = "A vulnerability was discovered and corrected in the Linux 2.6 kernel:

  The asn1 implementation in (a) the Linux kernel 2.4 before 2.4.36.6 and
  2.6 before 2.6.25.5, as used in the cifs and ip_nat_snmp_basic modules;
  and (b) the gxsnmp package; does not properly validate length values
  during decoding of ASN.1 BER data, which allows remote attackers
  to cause a denial of service (crash) or execute arbitrary code via
  (1) a length greater than the working buffer, which can lead to an
  unspecified overflow; (2) an oid length of zero, which can lead to an
  off-by-one error; or (3) an indefinite length for a primitive encoding.
  
  
  To update your kernel, please follow the directions located at:
  
  http://www.mandriva.com/en/security/kernelupdate";

tag_affected = "kernel on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-06/msg00019.php");
  script_id(830632);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2008:113");
  script_cve_id("CVE-2008-1673");
  script_name( "Mandriva Update for kernel MDVSA-2008:113 (kernel)");

  script_description(desc);
  script_summary("Check for the Version of kernel");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"actuator-kernel", rpm:"actuator-kernel~2.6.24.5~desktop~2mnb~1.0.5~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"actuator-kernel", rpm:"actuator-kernel~2.6.24.5~desktop586~2mnb~1.0.5~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"actuator-kernel", rpm:"actuator-kernel~2.6.24.5~laptop~2mnb~1.0.5~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"actuator-kernel", rpm:"actuator-kernel~2.6.24.5~server~2mnb~1.0.5~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"actuator-kernel-desktop586-latest", rpm:"actuator-kernel-desktop586-latest~1.0.5~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"actuator-kernel-desktop-latest", rpm:"actuator-kernel-desktop-latest~1.0.5~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"actuator-kernel-laptop-latest", rpm:"actuator-kernel-laptop-latest~1.0.5~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"actuator-kernel-server-latest", rpm:"actuator-kernel-server-latest~1.0.5~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel", rpm:"alsa_raoppcm-kernel~2.6.24.5~desktop~2mnb~0.5.1~2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel", rpm:"alsa_raoppcm-kernel~2.6.24.5~desktop586~2mnb~0.5.1~2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel", rpm:"alsa_raoppcm-kernel~2.6.24.5~laptop~2mnb~0.5.1~2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel", rpm:"alsa_raoppcm-kernel~2.6.24.5~server~2mnb~0.5.1~2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-desktop586-latest", rpm:"alsa_raoppcm-kernel-desktop586-latest~0.5.1~1.20080612.2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-desktop-latest", rpm:"alsa_raoppcm-kernel-desktop-latest~0.5.1~1.20080612.2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-laptop-latest", rpm:"alsa_raoppcm-kernel-laptop-latest~0.5.1~1.20080612.2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"alsa_raoppcm-kernel-server-latest", rpm:"alsa_raoppcm-kernel-server-latest~0.5.1~1.20080612.2mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel", rpm:"dkms-pcc-acpi-kernel~2.6.24.5~desktop~2mnb~0.9~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel", rpm:"dkms-pcc-acpi-kernel~2.6.24.5~desktop586~2mnb~0.9~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel", rpm:"dkms-pcc-acpi-kernel~2.6.24.5~laptop~2mnb~0.9~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel", rpm:"dkms-pcc-acpi-kernel~2.6.24.5~server~2mnb~0.9~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel-desktop586-latest", rpm:"dkms-pcc-acpi-kernel-desktop586-latest~0.9~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel-desktop-latest", rpm:"dkms-pcc-acpi-kernel-desktop-latest~0.9~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel-laptop-latest", rpm:"dkms-pcc-acpi-kernel-laptop-latest~0.9~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dkms-pcc-acpi-kernel-server-latest", rpm:"dkms-pcc-acpi-kernel-server-latest~0.9~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel", rpm:"drm-experimental-kernel~2.6.24.5~desktop~2mnb~2.3.0~1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel", rpm:"drm-experimental-kernel~2.6.24.5~desktop586~2mnb~2.3.0~1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel", rpm:"drm-experimental-kernel~2.6.24.5~laptop~2mnb~2.3.0~1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel", rpm:"drm-experimental-kernel~2.6.24.5~server~2mnb~2.3.0~1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel-desktop586-latest", rpm:"drm-experimental-kernel-desktop586-latest~2.3.0~1.20080612.1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel-desktop-latest", rpm:"drm-experimental-kernel-desktop-latest~2.3.0~1.20080612.1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel-laptop-latest", rpm:"drm-experimental-kernel-laptop-latest~2.3.0~1.20080612.1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drm-experimental-kernel-server-latest", rpm:"drm-experimental-kernel-server-latest~2.3.0~1.20080612.1.20080223.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel", rpm:"em8300-kernel~2.6.24.5~desktop~2mnb~0.16.4~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel", rpm:"em8300-kernel~2.6.24.5~desktop586~2mnb~0.16.4~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel", rpm:"em8300-kernel~2.6.24.5~laptop~2mnb~0.16.4~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel", rpm:"em8300-kernel~2.6.24.5~server~2mnb~0.16.4~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-desktop586-latest", rpm:"em8300-kernel-desktop586-latest~0.16.4~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-desktop-latest", rpm:"em8300-kernel-desktop-latest~0.16.4~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-laptop-latest", rpm:"em8300-kernel-laptop-latest~0.16.4~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"em8300-kernel-server-latest", rpm:"em8300-kernel-server-latest~0.16.4~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel", rpm:"et131x-kernel~2.6.24.5~desktop~2mnb~1.2.3~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel", rpm:"et131x-kernel~2.6.24.5~desktop586~2mnb~1.2.3~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel", rpm:"et131x-kernel~2.6.24.5~laptop~2mnb~1.2.3~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel", rpm:"et131x-kernel~2.6.24.5~server~2mnb~1.2.3~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel-desktop586-latest", rpm:"et131x-kernel-desktop586-latest~1.2.3~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel-desktop-latest", rpm:"et131x-kernel-desktop-latest~1.2.3~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel-laptop-latest", rpm:"et131x-kernel-laptop-latest~1.2.3~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"et131x-kernel-server-latest", rpm:"et131x-kernel-server-latest~1.2.3~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel", rpm:"fcdsl2-kernel~2.6.24.5~desktop~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel", rpm:"fcdsl2-kernel~2.6.24.5~desktop586~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel", rpm:"fcdsl2-kernel~2.6.24.5~laptop~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel", rpm:"fcdsl2-kernel~2.6.24.5~server~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel-desktop586-latest", rpm:"fcdsl2-kernel-desktop586-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel-desktop-latest", rpm:"fcdsl2-kernel-desktop-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel-laptop-latest", rpm:"fcdsl2-kernel-laptop-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl2-kernel-server-latest", rpm:"fcdsl2-kernel-server-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel", rpm:"fcdsl-kernel~2.6.24.5~desktop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel", rpm:"fcdsl-kernel~2.6.24.5~desktop586~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel", rpm:"fcdsl-kernel~2.6.24.5~laptop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel", rpm:"fcdsl-kernel~2.6.24.5~server~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel-desktop586-latest", rpm:"fcdsl-kernel-desktop586-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel-desktop-latest", rpm:"fcdsl-kernel-desktop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel-laptop-latest", rpm:"fcdsl-kernel-laptop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdsl-kernel-server-latest", rpm:"fcdsl-kernel-server-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel", rpm:"fcdslsl-kernel~2.6.24.5~desktop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel", rpm:"fcdslsl-kernel~2.6.24.5~desktop586~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel", rpm:"fcdslsl-kernel~2.6.24.5~laptop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel", rpm:"fcdslsl-kernel~2.6.24.5~server~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel-desktop586-latest", rpm:"fcdslsl-kernel-desktop586-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel-desktop-latest", rpm:"fcdslsl-kernel-desktop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel-laptop-latest", rpm:"fcdslsl-kernel-laptop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslsl-kernel-server-latest", rpm:"fcdslsl-kernel-server-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel", rpm:"fcdslslusb-kernel~2.6.24.5~desktop~2mnb~3.11.05~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel", rpm:"fcdslslusb-kernel~2.6.24.5~desktop586~2mnb~3.11.05~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel", rpm:"fcdslslusb-kernel~2.6.24.5~laptop~2mnb~3.11.05~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel", rpm:"fcdslslusb-kernel~2.6.24.5~server~2mnb~3.11.05~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel-desktop586-latest", rpm:"fcdslslusb-kernel-desktop586-latest~3.11.05~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel-desktop-latest", rpm:"fcdslslusb-kernel-desktop-latest~3.11.05~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel-laptop-latest", rpm:"fcdslslusb-kernel-laptop-latest~3.11.05~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslslusb-kernel-server-latest", rpm:"fcdslslusb-kernel-server-latest~3.11.05~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel", rpm:"fcdslusb2-kernel~2.6.24.5~desktop~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel", rpm:"fcdslusb2-kernel~2.6.24.5~desktop586~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel", rpm:"fcdslusb2-kernel~2.6.24.5~laptop~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel", rpm:"fcdslusb2-kernel~2.6.24.5~server~2mnb~3.11.07~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel-desktop586-latest", rpm:"fcdslusb2-kernel-desktop586-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel-desktop-latest", rpm:"fcdslusb2-kernel-desktop-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel-laptop-latest", rpm:"fcdslusb2-kernel-laptop-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb2-kernel-server-latest", rpm:"fcdslusb2-kernel-server-latest~3.11.07~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel", rpm:"fcdslusba-kernel~2.6.24.5~desktop~2mnb~3.11.05~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel", rpm:"fcdslusba-kernel~2.6.24.5~desktop586~2mnb~3.11.05~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel", rpm:"fcdslusba-kernel~2.6.24.5~laptop~2mnb~3.11.05~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel", rpm:"fcdslusba-kernel~2.6.24.5~server~2mnb~3.11.05~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel-desktop586-latest", rpm:"fcdslusba-kernel-desktop586-latest~3.11.05~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel-desktop-latest", rpm:"fcdslusba-kernel-desktop-latest~3.11.05~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel-laptop-latest", rpm:"fcdslusba-kernel-laptop-latest~3.11.05~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusba-kernel-server-latest", rpm:"fcdslusba-kernel-server-latest~3.11.05~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel", rpm:"fcdslusb-kernel~2.6.24.5~desktop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel", rpm:"fcdslusb-kernel~2.6.24.5~desktop586~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel", rpm:"fcdslusb-kernel~2.6.24.5~laptop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel", rpm:"fcdslusb-kernel~2.6.24.5~server~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel-desktop586-latest", rpm:"fcdslusb-kernel-desktop586-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel-desktop-latest", rpm:"fcdslusb-kernel-desktop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel-laptop-latest", rpm:"fcdslusb-kernel-laptop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcdslusb-kernel-server-latest", rpm:"fcdslusb-kernel-server-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel", rpm:"fcpci-kernel~2.6.24.5~desktop~2mnb~3.11.07~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel", rpm:"fcpci-kernel~2.6.24.5~desktop586~2mnb~3.11.07~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel", rpm:"fcpci-kernel~2.6.24.5~laptop~2mnb~3.11.07~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel", rpm:"fcpci-kernel~2.6.24.5~server~2mnb~3.11.07~6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel-desktop586-latest", rpm:"fcpci-kernel-desktop586-latest~3.11.07~1.20080612.6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel-desktop-latest", rpm:"fcpci-kernel-desktop-latest~3.11.07~1.20080612.6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel-laptop-latest", rpm:"fcpci-kernel-laptop-latest~3.11.07~1.20080612.6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcpci-kernel-server-latest", rpm:"fcpci-kernel-server-latest~3.11.07~1.20080612.6.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel", rpm:"fcusb2-kernel~2.6.24.5~desktop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel", rpm:"fcusb2-kernel~2.6.24.5~desktop586~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel", rpm:"fcusb2-kernel~2.6.24.5~laptop~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel", rpm:"fcusb2-kernel~2.6.24.5~server~2mnb~3.11.07~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel-desktop586-latest", rpm:"fcusb2-kernel-desktop586-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel-desktop-latest", rpm:"fcusb2-kernel-desktop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel-laptop-latest", rpm:"fcusb2-kernel-laptop-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb2-kernel-server-latest", rpm:"fcusb2-kernel-server-latest~3.11.07~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel", rpm:"fcusb-kernel~2.6.24.5~desktop~2mnb~3.11.04~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel", rpm:"fcusb-kernel~2.6.24.5~desktop586~2mnb~3.11.04~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel", rpm:"fcusb-kernel~2.6.24.5~laptop~2mnb~3.11.04~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel", rpm:"fcusb-kernel~2.6.24.5~server~2mnb~3.11.04~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel-desktop586-latest", rpm:"fcusb-kernel-desktop586-latest~3.11.04~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel-desktop-latest", rpm:"fcusb-kernel-desktop-latest~3.11.04~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel-laptop-latest", rpm:"fcusb-kernel-laptop-latest~3.11.04~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fcusb-kernel-server-latest", rpm:"fcusb-kernel-server-latest~3.11.04~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel", rpm:"fglrx-kernel~2.6.24.5~desktop~2mnb~8.471~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel", rpm:"fglrx-kernel~2.6.24.5~desktop586~2mnb~8.471~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel", rpm:"fglrx-kernel~2.6.24.5~laptop~2mnb~8.471~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel", rpm:"fglrx-kernel~2.6.24.5~server~2mnb~8.471~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop586-latest", rpm:"fglrx-kernel-desktop586-latest~8.471~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-desktop-latest", rpm:"fglrx-kernel-desktop-latest~8.471~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-laptop-latest", rpm:"fglrx-kernel-laptop-latest~8.471~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fglrx-kernel-server-latest", rpm:"fglrx-kernel-server-latest~8.471~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel", rpm:"fxusb_CZ-kernel~2.6.24.5~desktop~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel", rpm:"fxusb_CZ-kernel~2.6.24.5~desktop586~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel", rpm:"fxusb_CZ-kernel~2.6.24.5~laptop~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel", rpm:"fxusb_CZ-kernel~2.6.24.5~server~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel-desktop586-latest", rpm:"fxusb_CZ-kernel-desktop586-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel-desktop-latest", rpm:"fxusb_CZ-kernel-desktop-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel-laptop-latest", rpm:"fxusb_CZ-kernel-laptop-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb_CZ-kernel-server-latest", rpm:"fxusb_CZ-kernel-server-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel", rpm:"fxusb-kernel~2.6.24.5~desktop~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel", rpm:"fxusb-kernel~2.6.24.5~desktop586~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel", rpm:"fxusb-kernel~2.6.24.5~laptop~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel", rpm:"fxusb-kernel~2.6.24.5~server~2mnb~3.11.06~6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel-desktop586-latest", rpm:"fxusb-kernel-desktop586-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel-desktop-latest", rpm:"fxusb-kernel-desktop-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel-laptop-latest", rpm:"fxusb-kernel-laptop-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"fxusb-kernel-server-latest", rpm:"fxusb-kernel-server-latest~3.11.06~1.20080612.6mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel", rpm:"hsfmodem-kernel~2.6.24.5~desktop~2mnb~7.68.00.07~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel", rpm:"hsfmodem-kernel~2.6.24.5~desktop586~2mnb~7.68.00.07~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel", rpm:"hsfmodem-kernel~2.6.24.5~laptop~2mnb~7.68.00.07~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel", rpm:"hsfmodem-kernel~2.6.24.5~server~2mnb~7.68.00.07~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-desktop586-latest", rpm:"hsfmodem-kernel-desktop586-latest~7.68.00.07~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-desktop-latest", rpm:"hsfmodem-kernel-desktop-latest~7.68.00.07~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-laptop-latest", rpm:"hsfmodem-kernel-laptop-latest~7.68.00.07~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hsfmodem-kernel-server-latest", rpm:"hsfmodem-kernel-server-latest~7.68.00.07~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel", rpm:"ipw3945-kernel~2.6.24.5~desktop~2mnb~1.2.2~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel", rpm:"ipw3945-kernel~2.6.24.5~desktop586~2mnb~1.2.2~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel", rpm:"ipw3945-kernel~2.6.24.5~laptop~2mnb~1.2.2~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel", rpm:"ipw3945-kernel~2.6.24.5~server~2mnb~1.2.2~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel-desktop586-latest", rpm:"ipw3945-kernel-desktop586-latest~1.2.2~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel-desktop-latest", rpm:"ipw3945-kernel-desktop-latest~1.2.2~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel-laptop-latest", rpm:"ipw3945-kernel-laptop-latest~1.2.2~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipw3945-kernel-server-latest", rpm:"ipw3945-kernel-server-latest~1.2.2~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel", rpm:"iwlwifi-kernel~2.6.24.5~desktop~2mnb~1.2.25~5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel", rpm:"iwlwifi-kernel~2.6.24.5~desktop586~2mnb~1.2.25~5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel", rpm:"iwlwifi-kernel~2.6.24.5~laptop~2mnb~1.2.25~5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel", rpm:"iwlwifi-kernel~2.6.24.5~server~2mnb~1.2.25~5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel-desktop586-latest", rpm:"iwlwifi-kernel-desktop586-latest~1.2.25~1.20080612.5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel-desktop-latest", rpm:"iwlwifi-kernel-desktop-latest~1.2.25~1.20080612.5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel-laptop-latest", rpm:"iwlwifi-kernel-laptop-latest~1.2.25~1.20080612.5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iwlwifi-kernel-server-latest", rpm:"iwlwifi-kernel-server-latest~1.2.25~1.20080612.5mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586", rpm:"kernel-desktop586~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586-devel", rpm:"kernel-desktop586-devel~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586-devel-latest", rpm:"kernel-desktop586-devel-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop586-latest", rpm:"kernel-desktop586-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-devel-latest", rpm:"kernel-desktop-devel-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-latest", rpm:"kernel-desktop-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-laptop", rpm:"kernel-laptop~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-laptop-devel", rpm:"kernel-laptop-devel~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-laptop-devel-latest", rpm:"kernel-laptop-devel-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-laptop-latest", rpm:"kernel-laptop-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server", rpm:"kernel-server~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server-devel", rpm:"kernel-server-devel~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server-devel-latest", rpm:"kernel-server-devel-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-server-latest", rpm:"kernel-server-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.24.5~2mnb~1~1mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel", rpm:"kqemu-kernel~2.6.24.5~desktop~2mnb~1.3.0pre11~15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel", rpm:"kqemu-kernel~2.6.24.5~desktop586~2mnb~1.3.0pre11~15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel", rpm:"kqemu-kernel~2.6.24.5~laptop~2mnb~1.3.0pre11~15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel", rpm:"kqemu-kernel~2.6.24.5~server~2mnb~1.3.0pre11~15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel-desktop586-latest", rpm:"kqemu-kernel-desktop586-latest~1.3.0pre11~1.20080612.15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel-desktop-latest", rpm:"kqemu-kernel-desktop-latest~1.3.0pre11~1.20080612.15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel-laptop-latest", rpm:"kqemu-kernel-laptop-latest~1.3.0pre11~1.20080612.15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kernel-server-latest", rpm:"kqemu-kernel-server-latest~1.3.0pre11~1.20080612.15", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel", rpm:"libafs-kernel~2.6.24.5~desktop~2mnb~1.4.6~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel", rpm:"libafs-kernel~2.6.24.5~desktop586~2mnb~1.4.6~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel", rpm:"libafs-kernel~2.6.24.5~laptop~2mnb~1.4.6~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel", rpm:"libafs-kernel~2.6.24.5~server~2mnb~1.4.6~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-desktop586-latest", rpm:"libafs-kernel-desktop586-latest~1.4.6~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-desktop-latest", rpm:"libafs-kernel-desktop-latest~1.4.6~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-laptop-latest", rpm:"libafs-kernel-laptop-latest~1.4.6~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libafs-kernel-server-latest", rpm:"libafs-kernel-server-latest~1.4.6~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel", rpm:"lirc-kernel~2.6.24.5~desktop~2mnb~0.8.2~1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel", rpm:"lirc-kernel~2.6.24.5~desktop586~2mnb~0.8.2~1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel", rpm:"lirc-kernel~2.6.24.5~laptop~2mnb~0.8.2~1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel", rpm:"lirc-kernel~2.6.24.5~server~2mnb~0.8.2~1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-desktop586-latest", rpm:"lirc-kernel-desktop586-latest~0.8.2~1.20080612.1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-desktop-latest", rpm:"lirc-kernel-desktop-latest~0.8.2~1.20080612.1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-laptop-latest", rpm:"lirc-kernel-laptop-latest~0.8.2~1.20080612.1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kernel-server-latest", rpm:"lirc-kernel-server-latest~0.8.2~1.20080612.1.20080310.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel", rpm:"lzma-kernel~2.6.24.5~desktop~2mnb~4.43~21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel", rpm:"lzma-kernel~2.6.24.5~desktop586~2mnb~4.43~21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel", rpm:"lzma-kernel~2.6.24.5~laptop~2mnb~4.43~21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel", rpm:"lzma-kernel~2.6.24.5~server~2mnb~4.43~21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-desktop586-latest", rpm:"lzma-kernel-desktop586-latest~4.43~1.20080612.21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-desktop-latest", rpm:"lzma-kernel-desktop-latest~4.43~1.20080612.21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-laptop-latest", rpm:"lzma-kernel-laptop-latest~4.43~1.20080612.21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lzma-kernel-server-latest", rpm:"lzma-kernel-server-latest~4.43~1.20080612.21mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel", rpm:"m560x-kernel~2.6.24.5~desktop~2mnb~0.4.0~0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel", rpm:"m560x-kernel~2.6.24.5~desktop586~2mnb~0.4.0~0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel", rpm:"m560x-kernel~2.6.24.5~laptop~2mnb~0.4.0~0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel", rpm:"m560x-kernel~2.6.24.5~server~2mnb~0.4.0~0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel-desktop586-latest", rpm:"m560x-kernel-desktop586-latest~0.4.0~1.20080612.0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel-desktop-latest", rpm:"m560x-kernel-desktop-latest~0.4.0~1.20080612.0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel-laptop-latest", rpm:"m560x-kernel-laptop-latest~0.4.0~1.20080612.0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"m560x-kernel-server-latest", rpm:"m560x-kernel-server-latest~0.4.0~1.20080612.0.20080229.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel", rpm:"madwifi-kernel~2.6.24.5~desktop~2mnb~0.9.3.3~5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel", rpm:"madwifi-kernel~2.6.24.5~desktop586~2mnb~0.9.3.3~5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel", rpm:"madwifi-kernel~2.6.24.5~laptop~2mnb~0.9.3.3~5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel", rpm:"madwifi-kernel~2.6.24.5~server~2mnb~0.9.3.3~5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop586-latest", rpm:"madwifi-kernel-desktop586-latest~0.9.3.3~1.20080612.5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-desktop-latest", rpm:"madwifi-kernel-desktop-latest~0.9.3.3~1.20080612.5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-laptop-latest", rpm:"madwifi-kernel-laptop-latest~0.9.3.3~1.20080612.5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"madwifi-kernel-server-latest", rpm:"madwifi-kernel-server-latest~0.9.3.3~1.20080612.5.r3114mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel", rpm:"ndiswrapper-kernel~2.6.24.5~desktop~2mnb~1.52~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel", rpm:"ndiswrapper-kernel~2.6.24.5~desktop586~2mnb~1.52~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel", rpm:"ndiswrapper-kernel~2.6.24.5~laptop~2mnb~1.52~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel", rpm:"ndiswrapper-kernel~2.6.24.5~server~2mnb~1.52~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel-desktop586-latest", rpm:"ndiswrapper-kernel-desktop586-latest~1.52~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel-desktop-latest", rpm:"ndiswrapper-kernel-desktop-latest~1.52~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel-laptop-latest", rpm:"ndiswrapper-kernel-laptop-latest~1.52~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kernel-server-latest", rpm:"ndiswrapper-kernel-server-latest~1.52~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel", rpm:"nvidia71xx-kernel~2.6.24.5~desktop~2mnb~71.86.04~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel", rpm:"nvidia71xx-kernel~2.6.24.5~desktop586~2mnb~71.86.04~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel", rpm:"nvidia71xx-kernel~2.6.24.5~laptop~2mnb~71.86.04~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel", rpm:"nvidia71xx-kernel~2.6.24.5~server~2mnb~71.86.04~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-desktop586-latest", rpm:"nvidia71xx-kernel-desktop586-latest~71.86.04~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-desktop-latest", rpm:"nvidia71xx-kernel-desktop-latest~71.86.04~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-laptop-latest", rpm:"nvidia71xx-kernel-laptop-latest~71.86.04~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia71xx-kernel-server-latest", rpm:"nvidia71xx-kernel-server-latest~71.86.04~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel", rpm:"nvidia96xx-kernel~2.6.24.5~desktop~2mnb~96.43.05~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel", rpm:"nvidia96xx-kernel~2.6.24.5~desktop586~2mnb~96.43.05~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel", rpm:"nvidia96xx-kernel~2.6.24.5~laptop~2mnb~96.43.05~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel", rpm:"nvidia96xx-kernel~2.6.24.5~server~2mnb~96.43.05~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop586-latest", rpm:"nvidia96xx-kernel-desktop586-latest~96.43.05~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-desktop-latest", rpm:"nvidia96xx-kernel-desktop-latest~96.43.05~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-laptop-latest", rpm:"nvidia96xx-kernel-laptop-latest~96.43.05~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia96xx-kernel-server-latest", rpm:"nvidia96xx-kernel-server-latest~96.43.05~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel", rpm:"nvidia-current-kernel~2.6.24.5~desktop~2mnb~169.12~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel", rpm:"nvidia-current-kernel~2.6.24.5~desktop586~2mnb~169.12~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel", rpm:"nvidia-current-kernel~2.6.24.5~laptop~2mnb~169.12~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel", rpm:"nvidia-current-kernel~2.6.24.5~server~2mnb~169.12~4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop586-latest", rpm:"nvidia-current-kernel-desktop586-latest~169.12~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-desktop-latest", rpm:"nvidia-current-kernel-desktop-latest~169.12~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-laptop-latest", rpm:"nvidia-current-kernel-laptop-latest~169.12~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nvidia-current-kernel-server-latest", rpm:"nvidia-current-kernel-server-latest~169.12~1.20080612.4mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel", rpm:"omfs-kernel~2.6.24.5~desktop~2mnb~0.7.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel", rpm:"omfs-kernel~2.6.24.5~desktop586~2mnb~0.7.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel", rpm:"omfs-kernel~2.6.24.5~laptop~2mnb~0.7.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel", rpm:"omfs-kernel~2.6.24.5~server~2mnb~0.7.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel-desktop586-latest", rpm:"omfs-kernel-desktop586-latest~0.7.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel-desktop-latest", rpm:"omfs-kernel-desktop-latest~0.7.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel-laptop-latest", rpm:"omfs-kernel-laptop-latest~0.7.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omfs-kernel-server-latest", rpm:"omfs-kernel-server-latest~0.7.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel", rpm:"opencbm-kernel~2.6.24.5~desktop~2mnb~0.4.2a~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel", rpm:"opencbm-kernel~2.6.24.5~desktop586~2mnb~0.4.2a~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel", rpm:"opencbm-kernel~2.6.24.5~laptop~2mnb~0.4.2a~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel", rpm:"opencbm-kernel~2.6.24.5~server~2mnb~0.4.2a~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel-desktop586-latest", rpm:"opencbm-kernel-desktop586-latest~0.4.2a~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel-desktop-latest", rpm:"opencbm-kernel-desktop-latest~0.4.2a~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel-laptop-latest", rpm:"opencbm-kernel-laptop-latest~0.4.2a~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"opencbm-kernel-server-latest", rpm:"opencbm-kernel-server-latest~0.4.2a~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel", rpm:"ov51x-jpeg-kernel~2.6.24.5~desktop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel", rpm:"ov51x-jpeg-kernel~2.6.24.5~desktop586~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel", rpm:"ov51x-jpeg-kernel~2.6.24.5~laptop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel", rpm:"ov51x-jpeg-kernel~2.6.24.5~server~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel-desktop586-latest", rpm:"ov51x-jpeg-kernel-desktop586-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel-desktop-latest", rpm:"ov51x-jpeg-kernel-desktop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel-laptop-latest", rpm:"ov51x-jpeg-kernel-laptop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ov51x-jpeg-kernel-server-latest", rpm:"ov51x-jpeg-kernel-server-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel", rpm:"qc-usb-messenger-kernel~2.6.24.5~desktop~2mnb~1.7~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel", rpm:"qc-usb-messenger-kernel~2.6.24.5~desktop586~2mnb~1.7~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel", rpm:"qc-usb-messenger-kernel~2.6.24.5~laptop~2mnb~1.7~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel", rpm:"qc-usb-messenger-kernel~2.6.24.5~server~2mnb~1.7~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel-desktop586-latest", rpm:"qc-usb-messenger-kernel-desktop586-latest~1.7~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel-desktop-latest", rpm:"qc-usb-messenger-kernel-desktop-latest~1.7~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel-laptop-latest", rpm:"qc-usb-messenger-kernel-laptop-latest~1.7~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qc-usb-messenger-kernel-server-latest", rpm:"qc-usb-messenger-kernel-server-latest~1.7~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel", rpm:"r5u870-kernel~2.6.24.5~desktop~2mnb~0.11.0~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel", rpm:"r5u870-kernel~2.6.24.5~desktop586~2mnb~0.11.0~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel", rpm:"r5u870-kernel~2.6.24.5~laptop~2mnb~0.11.0~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel", rpm:"r5u870-kernel~2.6.24.5~server~2mnb~0.11.0~3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel-desktop586-latest", rpm:"r5u870-kernel-desktop586-latest~0.11.0~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel-desktop-latest", rpm:"r5u870-kernel-desktop-latest~0.11.0~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel-laptop-latest", rpm:"r5u870-kernel-laptop-latest~0.11.0~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"r5u870-kernel-server-latest", rpm:"r5u870-kernel-server-latest~0.11.0~1.20080612.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel", rpm:"realcrypt-kernel~2.6.24.5~desktop~2mnb~4.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel", rpm:"realcrypt-kernel~2.6.24.5~desktop586~2mnb~4.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel", rpm:"realcrypt-kernel~2.6.24.5~laptop~2mnb~4.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel", rpm:"realcrypt-kernel~2.6.24.5~server~2mnb~4.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel-desktop586-latest", rpm:"realcrypt-kernel-desktop586-latest~4.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel-desktop-latest", rpm:"realcrypt-kernel-desktop-latest~4.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel-laptop-latest", rpm:"realcrypt-kernel-laptop-latest~4.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"realcrypt-kernel-server-latest", rpm:"realcrypt-kernel-server-latest~4.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel", rpm:"slmodem-kernel~2.6.24.5~desktop~2mnb~2.9.11~0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel", rpm:"slmodem-kernel~2.6.24.5~desktop586~2mnb~2.9.11~0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel", rpm:"slmodem-kernel~2.6.24.5~laptop~2mnb~2.9.11~0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel", rpm:"slmodem-kernel~2.6.24.5~server~2mnb~2.9.11~0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-desktop586-latest", rpm:"slmodem-kernel-desktop586-latest~2.9.11~1.20080612.0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-desktop-latest", rpm:"slmodem-kernel-desktop-latest~2.9.11~1.20080612.0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-laptop-latest", rpm:"slmodem-kernel-laptop-latest~2.9.11~1.20080612.0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"slmodem-kernel-server-latest", rpm:"slmodem-kernel-server-latest~2.9.11~1.20080612.0.20070813.3mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel", rpm:"squashfs-kernel~2.6.24.5~desktop~2mnb~3.3~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel", rpm:"squashfs-kernel~2.6.24.5~desktop586~2mnb~3.3~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel", rpm:"squashfs-kernel~2.6.24.5~laptop~2mnb~3.3~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel", rpm:"squashfs-kernel~2.6.24.5~server~2mnb~3.3~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel-desktop586-latest", rpm:"squashfs-kernel-desktop586-latest~3.3~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel-desktop-latest", rpm:"squashfs-kernel-desktop-latest~3.3~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel-laptop-latest", rpm:"squashfs-kernel-laptop-latest~3.3~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-kernel-server-latest", rpm:"squashfs-kernel-server-latest~3.3~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel", rpm:"squashfs-lzma-kernel~2.6.24.5~desktop~2mnb~3.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel", rpm:"squashfs-lzma-kernel~2.6.24.5~desktop586~2mnb~3.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel", rpm:"squashfs-lzma-kernel~2.6.24.5~laptop~2mnb~3.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel", rpm:"squashfs-lzma-kernel~2.6.24.5~server~2mnb~3.3~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-desktop586-latest", rpm:"squashfs-lzma-kernel-desktop586-latest~3.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-desktop-latest", rpm:"squashfs-lzma-kernel-desktop-latest~3.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-laptop-latest", rpm:"squashfs-lzma-kernel-laptop-latest~3.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"squashfs-lzma-kernel-server-latest", rpm:"squashfs-lzma-kernel-server-latest~3.3~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel", rpm:"syntek-kernel~2.6.24.5~desktop~2mnb~1.3.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel", rpm:"syntek-kernel~2.6.24.5~desktop586~2mnb~1.3.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel", rpm:"syntek-kernel~2.6.24.5~laptop~2mnb~1.3.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel", rpm:"syntek-kernel~2.6.24.5~server~2mnb~1.3.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel-desktop586-latest", rpm:"syntek-kernel-desktop586-latest~1.3.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel-desktop-latest", rpm:"syntek-kernel-desktop-latest~1.3.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel-laptop-latest", rpm:"syntek-kernel-laptop-latest~1.3.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"syntek-kernel-server-latest", rpm:"syntek-kernel-server-latest~1.3.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel", rpm:"tp_smapi-kernel~2.6.24.5~desktop~2mnb~0.36~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel", rpm:"tp_smapi-kernel~2.6.24.5~desktop586~2mnb~0.36~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel", rpm:"tp_smapi-kernel~2.6.24.5~laptop~2mnb~0.36~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel", rpm:"tp_smapi-kernel~2.6.24.5~server~2mnb~0.36~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel-desktop586-latest", rpm:"tp_smapi-kernel-desktop586-latest~0.36~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel-desktop-latest", rpm:"tp_smapi-kernel-desktop-latest~0.36~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel-laptop-latest", rpm:"tp_smapi-kernel-laptop-latest~0.36~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tp_smapi-kernel-server-latest", rpm:"tp_smapi-kernel-server-latest~0.36~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel", rpm:"unicorn-kernel~2.6.24.5~desktop~2mnb~0.9.3~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel", rpm:"unicorn-kernel~2.6.24.5~desktop586~2mnb~0.9.3~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel", rpm:"unicorn-kernel~2.6.24.5~laptop~2mnb~0.9.3~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel", rpm:"unicorn-kernel~2.6.24.5~server~2mnb~0.9.3~7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel-desktop586-latest", rpm:"unicorn-kernel-desktop586-latest~0.9.3~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel-desktop-latest", rpm:"unicorn-kernel-desktop-latest~0.9.3~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel-laptop-latest", rpm:"unicorn-kernel-laptop-latest~0.9.3~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unicorn-kernel-server-latest", rpm:"unicorn-kernel-server-latest~0.9.3~1.20080612.7mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel", rpm:"unionfs-kernel~2.6.24.5~desktop~2mnb~1.4.1mdv2008.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel", rpm:"unionfs-kernel~2.6.24.5~desktop586~2mnb~1.4.1mdv2008.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel", rpm:"unionfs-kernel~2.6.24.5~laptop~2mnb~1.4.1mdv2008.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel", rpm:"unionfs-kernel~2.6.24.5~server~2mnb~1.4.1mdv2008.1~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel-desktop586-latest", rpm:"unionfs-kernel-desktop586-latest~1.4.1mdv2008.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel-desktop-latest", rpm:"unionfs-kernel-desktop-latest~1.4.1mdv2008.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel-laptop-latest", rpm:"unionfs-kernel-laptop-latest~1.4.1mdv2008.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"unionfs-kernel-server-latest", rpm:"unionfs-kernel-server-latest~1.4.1mdv2008.1~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel", rpm:"vboxadd-kernel~2.6.24.5~desktop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel", rpm:"vboxadd-kernel~2.6.24.5~desktop586~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel", rpm:"vboxadd-kernel~2.6.24.5~laptop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel", rpm:"vboxadd-kernel~2.6.24.5~server~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel-desktop586-latest", rpm:"vboxadd-kernel-desktop586-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel-desktop-latest", rpm:"vboxadd-kernel-desktop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel-laptop-latest", rpm:"vboxadd-kernel-laptop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxadd-kernel-server-latest", rpm:"vboxadd-kernel-server-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel", rpm:"vboxvfs-kernel~2.6.24.5~desktop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel", rpm:"vboxvfs-kernel~2.6.24.5~desktop586~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel", rpm:"vboxvfs-kernel~2.6.24.5~laptop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel", rpm:"vboxvfs-kernel~2.6.24.5~server~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel-desktop586-latest", rpm:"vboxvfs-kernel-desktop586-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel-desktop-latest", rpm:"vboxvfs-kernel-desktop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel-laptop-latest", rpm:"vboxvfs-kernel-laptop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vboxvfs-kernel-server-latest", rpm:"vboxvfs-kernel-server-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel", rpm:"virtualbox-kernel~2.6.24.5~desktop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel", rpm:"virtualbox-kernel~2.6.24.5~desktop586~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel", rpm:"virtualbox-kernel~2.6.24.5~laptop~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel", rpm:"virtualbox-kernel~2.6.24.5~server~2mnb~1.5.6~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop586-latest", rpm:"virtualbox-kernel-desktop586-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-desktop-latest", rpm:"virtualbox-kernel-desktop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-laptop-latest", rpm:"virtualbox-kernel-laptop-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-kernel-server-latest", rpm:"virtualbox-kernel-server-latest~1.5.6~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel", rpm:"vpnclient-kernel~2.6.24.5~desktop~2mnb~4.8.01.0640~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel", rpm:"vpnclient-kernel~2.6.24.5~desktop586~2mnb~4.8.01.0640~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel", rpm:"vpnclient-kernel~2.6.24.5~laptop~2mnb~4.8.01.0640~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel", rpm:"vpnclient-kernel~2.6.24.5~server~2mnb~4.8.01.0640~1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop586-latest", rpm:"vpnclient-kernel-desktop586-latest~4.8.01.0640~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-desktop-latest", rpm:"vpnclient-kernel-desktop-latest~4.8.01.0640~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-laptop-latest", rpm:"vpnclient-kernel-laptop-latest~4.8.01.0640~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vpnclient-kernel-server-latest", rpm:"vpnclient-kernel-server-latest~4.8.01.0640~1.20080612.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.24.5~2mnb1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gspca-kernel", rpm:"gspca-kernel~2.6.24.5~desktop~2mnb~1.00.20~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gspca-kernel", rpm:"gspca-kernel~2.6.24.5~laptop~2mnb~1.00.20~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gspca-kernel", rpm:"gspca-kernel~2.6.24.5~server~2mnb~1.00.20~2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gspca-kernel-desktop-latest", rpm:"gspca-kernel-desktop-latest~1.00.20~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gspca-kernel-laptop-latest", rpm:"gspca-kernel-laptop-latest~1.00.20~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gspca-kernel-server-latest", rpm:"gspca-kernel-server-latest~1.00.20~1.20080612.2mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for Mesa openSUSE-SU-2013:1188-1 (Mesa)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(850506);
  script_version("$Revision: 74 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 13:29:03 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-19 14:05:28 +0530 (Tue, 19 Nov 2013)");
  script_cve_id("CVE-2013-1872");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("SuSE Update for Mesa openSUSE-SU-2013:1188-1 (Mesa)");

  tag_insight = "
  Mesa was updated to fix a security problem in the Intel
  drivers, where potentially remote attackers via 3D models
  could inject code.

  (CVE-2013-1872 - i965: fix problem with constant out of
  bounds access (bnc #828007).)";

  tag_affected = "Mesa on openSUSE 12.2";

  tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }

  script_description(desc);
  script_xref(name: "openSUSE-SU", value: "2013:1188_1");
  script_xref(name: "URL" , value: "http://lists.opensuse.org/opensuse-security-announce/2013-07/msg00019.html");
  script_summary("Check for the Version of Mesa");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"Mesa", rpm:"Mesa~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-debuginfo", rpm:"Mesa-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-debugsource", rpm:"Mesa-debugsource~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-devel", rpm:"Mesa-devel~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libEGL-devel", rpm:"Mesa-libEGL-devel~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libEGL1", rpm:"Mesa-libEGL1~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libEGL1-debuginfo", rpm:"Mesa-libEGL1-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGL-devel", rpm:"Mesa-libGL-devel~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGL1", rpm:"Mesa-libGL1~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGL1-debuginfo", rpm:"Mesa-libGL1-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel", rpm:"Mesa-libGLESv1_CM-devel~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv1_CM1", rpm:"Mesa-libGLESv1_CM1~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv1_CM1-debuginfo", rpm:"Mesa-libGLESv1_CM1-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv2-2", rpm:"Mesa-libGLESv2-2~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv2-2-debuginfo", rpm:"Mesa-libGLESv2-2-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv2-devel", rpm:"Mesa-libGLESv2-devel~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLU-devel", rpm:"Mesa-libGLU-devel~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLU1", rpm:"Mesa-libGLU1~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLU1-debuginfo", rpm:"Mesa-libGLU1-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libIndirectGL1", rpm:"Mesa-libIndirectGL1~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libIndirectGL1-debuginfo", rpm:"Mesa-libIndirectGL1-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libglapi0", rpm:"Mesa-libglapi0~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libglapi0-debuginfo", rpm:"Mesa-libglapi0-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libOSMesa8", rpm:"libOSMesa8~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libOSMesa8-debuginfo", rpm:"libOSMesa8-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_nouveau", rpm:"libXvMC_nouveau~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_nouveau-debuginfo", rpm:"libXvMC_nouveau-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r300", rpm:"libXvMC_r300~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r300-debuginfo", rpm:"libXvMC_r300-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r600", rpm:"libXvMC_r600~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r600-debuginfo", rpm:"libXvMC_r600-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_softpipe", rpm:"libXvMC_softpipe~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_softpipe-debuginfo", rpm:"libXvMC_softpipe-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgbm-devel", rpm:"libgbm-devel~0.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~0.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgbm1-debuginfo", rpm:"libgbm1-debuginfo~0.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_nouveau", rpm:"libvdpau_nouveau~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_nouveau-debuginfo", rpm:"libvdpau_nouveau-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r300", rpm:"libvdpau_r300~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r300-debuginfo", rpm:"libvdpau_r300-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r600", rpm:"libvdpau_r600~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r600-debuginfo", rpm:"libvdpau_r600-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_softpipe", rpm:"libvdpau_softpipe~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_softpipe-debuginfo", rpm:"libvdpau_softpipe-debuginfo~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxatracker-devel", rpm:"libxatracker-devel~1.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxatracker1", rpm:"libxatracker1~1.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxatracker1-debuginfo", rpm:"libxatracker1-debuginfo~1.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-32bit", rpm:"Mesa-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-debuginfo-32bit", rpm:"Mesa-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-devel-32bit", rpm:"Mesa-devel-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libEGL-devel-32bit", rpm:"Mesa-libEGL-devel-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libEGL1-32bit", rpm:"Mesa-libEGL1-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libEGL1-debuginfo-32bit", rpm:"Mesa-libEGL1-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGL-devel-32bit", rpm:"Mesa-libGL-devel-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGL1-32bit", rpm:"Mesa-libGL1-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGL1-debuginfo-32bit", rpm:"Mesa-libGL1-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv1_CM-devel-32bit", rpm:"Mesa-libGLESv1_CM-devel-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv1_CM1-32bit", rpm:"Mesa-libGLESv1_CM1-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv1_CM1-debuginfo-32bit", rpm:"Mesa-libGLESv1_CM1-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv2-2-32bit", rpm:"Mesa-libGLESv2-2-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv2-2-debuginfo-32bit", rpm:"Mesa-libGLESv2-2-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLESv2-devel-32bit", rpm:"Mesa-libGLESv2-devel-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLU-devel-32bit", rpm:"Mesa-libGLU-devel-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLU1-32bit", rpm:"Mesa-libGLU1-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libGLU1-debuginfo-32bit", rpm:"Mesa-libGLU1-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libIndirectGL1-32bit", rpm:"Mesa-libIndirectGL1-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libIndirectGL1-debuginfo-32bit", rpm:"Mesa-libIndirectGL1-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libglapi0-32bit", rpm:"Mesa-libglapi0-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Mesa-libglapi0-debuginfo-32bit", rpm:"Mesa-libglapi0-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libOSMesa8-32bit", rpm:"libOSMesa8-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libOSMesa8-debuginfo-32bit", rpm:"libOSMesa8-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_nouveau-32bit", rpm:"libXvMC_nouveau-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_nouveau-debuginfo-32bit", rpm:"libXvMC_nouveau-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r300-32bit", rpm:"libXvMC_r300-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r300-debuginfo-32bit", rpm:"libXvMC_r300-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r600-32bit", rpm:"libXvMC_r600-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_r600-debuginfo-32bit", rpm:"libXvMC_r600-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_softpipe-32bit", rpm:"libXvMC_softpipe-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libXvMC_softpipe-debuginfo-32bit", rpm:"libXvMC_softpipe-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgbm-devel-32bit", rpm:"libgbm-devel-32bit~0.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgbm1-32bit", rpm:"libgbm1-32bit~0.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgbm1-debuginfo-32bit", rpm:"libgbm1-debuginfo-32bit~0.0.0~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_nouveau-32bit", rpm:"libvdpau_nouveau-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_nouveau-debuginfo-32bit", rpm:"libvdpau_nouveau-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r300-32bit", rpm:"libvdpau_r300-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r300-debuginfo-32bit", rpm:"libvdpau_r300-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r600-32bit", rpm:"libvdpau_r600-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_r600-debuginfo-32bit", rpm:"libvdpau_r600-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_softpipe-32bit", rpm:"libvdpau_softpipe-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvdpau_softpipe-debuginfo-32bit", rpm:"libvdpau_softpipe-debuginfo-32bit~8.0.4~20.27.1", rls:"openSUSE12.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
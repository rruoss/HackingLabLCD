###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for XFree86 CESA-2008:0512-01 centos2 i386
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
tag_insight = "XFree86 is an implementation of the X Window System, which provides the
  core functionality for the Linux graphical desktop.

  An input validation flaw was discovered in X.org's Security and Record
  extensions. A malicious authorized client could exploit this issue to cause
  a denial of service (crash) or, potentially, execute arbitrary code with
  root privileges on the X.Org server. (CVE-2008-1377)
  
  An integer overflow flaw was found in X.org's Render extension. A malicious
  authorized client could exploit this issue to cause a denial of service
  (crash) or, potentially, execute arbitrary code with root privileges on the
  X.Org server. (CVE-2008-2360)
  
  An input validation flaw was discovered in X.org's MIT-SHM extension. A
  client connected to the X.org server could read arbitrary server memory.
  This could result in the sensitive data of other users of the X.org server
  being disclosed. (CVE-2008-1379)
  
  Users of XFree86 are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "XFree86 on CentOS 2";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-June/014977.html");
  script_id(880297);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2008:0512-01");
  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360");
  script_name( "CentOS Update for XFree86 CESA-2008:0512-01 centos2 i386");

  script_description(desc);
  script_summary("Check for the Version of XFree86");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS2")
{

  if ((res = isrpmvuln(pkg:"XFree86-100dpi-fonts", rpm:"XFree86-100dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86", rpm:"XFree86~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-75dpi-fonts", rpm:"XFree86-75dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-cyrillic-fonts", rpm:"XFree86-cyrillic-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-devel", rpm:"XFree86-devel~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-doc", rpm:"XFree86-doc~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-100dpi-fonts", rpm:"XFree86-ISO8859-15-100dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-15-75dpi-fonts", rpm:"XFree86-ISO8859-15-75dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-100dpi-fonts", rpm:"XFree86-ISO8859-2-100dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-2-75dpi-fonts", rpm:"XFree86-ISO8859-2-75dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-100dpi-fonts", rpm:"XFree86-ISO8859-9-100dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-ISO8859-9-75dpi-fonts", rpm:"XFree86-ISO8859-9-75dpi-fonts~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-libs", rpm:"XFree86-libs~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-tools", rpm:"XFree86-tools~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-twm", rpm:"XFree86-twm~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xdm", rpm:"XFree86-xdm~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xf86cfg", rpm:"XFree86-xf86cfg~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-xfs", rpm:"XFree86-xfs~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xnest", rpm:"XFree86-Xnest~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"XFree86-Xvfb", rpm:"XFree86-Xvfb~4.1.0~88.EL", rls:"CentOS2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

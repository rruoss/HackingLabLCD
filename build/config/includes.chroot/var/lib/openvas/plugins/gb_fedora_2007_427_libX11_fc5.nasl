###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for libX11 FEDORA-2007-427
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
tag_insight = "X.Org X11 libX11 runtime library

  ---------------------------------------------------------------------
  
  * Fri Apr  6 2007 Adam Jackson &lt;ajax redhat com&gt; 1.0.0-4
  - libX11-cve-2007-1667.patch: Fix CVE 2007-1667
  * Tue Jun 20 2006 Mike A. Harris &lt;mharris redhat com&gt; 1.0.1-3.FC5.0
  - Added libX11-1.0.1-setuid.diff to fix potential security issue (#196094)
  - Change dependency on &quot;filesystem&quot; package to &quot;xorg-x11-filesystem&quot; package,
    so we can control this dep centrally.
  - Added NEWS to doc list";

tag_affected = "libX11 on Fedora Core 5";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-April/msg00030.html");
  script_id(861441);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-1667");
  script_xref(name: "FEDORA", value: "2007-427");
  script_name( "Fedora Update for libX11 FEDORA-2007-427");

  script_description(desc);
  script_summary("Check for the Version of libX11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora_core", "login/SSH/success", "ssh/login/release");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"libX11", rpm:"libX11~1.0.0~4.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/libX11-debuginfo", rpm:"x86_64/debug/libX11-debuginfo~1.0.0~4.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/libX11-devel", rpm:"x86_64/libX11-devel~1.0.0~4.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/libX11", rpm:"x86_64/libX11~1.0.0~4.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/libX11-debuginfo", rpm:"i386/debug/libX11-debuginfo~1.0.0~4.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/libX11-devel", rpm:"i386/libX11-devel~1.0.0~4.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/libX11", rpm:"i386/libX11~1.0.0~4.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

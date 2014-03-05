###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for Thunar FEDORA-2007-4368
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
tag_affected = "Thunar on Fedora 8";
tag_insight = "Thunar is a new modern file manager for the Xfce Desktop Environment.
  It has been designed from the ground up to be fast and easy-to-use.
  Its user interface is clean and intuitive, and does not include any
  confusing or useless options. Thunar is fast and responsive with a
  good start up time and directory load time.";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-December/msg00563.html");
  script_id(861458);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2007-4368");
  script_name( "Fedora Update for Thunar FEDORA-2007-4368");

  script_description(desc);
  script_summary("Check for the Version of Thunar");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
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

if(release == "FC8")
{

  if ((res = isrpmvuln(pkg:"Thunar", rpm:"Thunar~0.9.0~2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Thunar", rpm:"Thunar~0.9.0~2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Thunar-debuginfo", rpm:"Thunar-debuginfo~0.9.0~2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Thunar-devel", rpm:"Thunar-devel~0.9.0~2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Thunar-debuginfo", rpm:"Thunar-debuginfo~0.9.0~2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Thunar", rpm:"Thunar~0.9.0~2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"Thunar-devel", rpm:"Thunar-devel~0.9.0~2.fc8", rls:"FC8")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for beagle MDVA-2010:198 (beagle)
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
tag_affected = "beagle on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64";
tag_insight = "It was discovered the mozilla-thunderbird-beagle packages wasn't
  built against the latest mozilla-thunderbird 3.0.8. The fixed packages
  addresses this problem.";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-09/msg00029.php");
  script_id(831161);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-27 08:14:44 +0200 (Mon, 27 Sep 2010)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVA", value: "2010:198");
  script_name("Mandriva Update for beagle MDVA-2010:198 (beagle)");

  script_description(desc);
  script_summary("Check for the Version of beagle");
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

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"beagle", rpm:"beagle~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-crawl-system", rpm:"beagle-crawl-system~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-doc", rpm:"beagle-doc~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-evolution", rpm:"beagle-evolution~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-gui", rpm:"beagle-gui~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-gui-qt", rpm:"beagle-gui-qt~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"beagle-libs", rpm:"beagle-libs~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"firefox-ext-beagle", rpm:"firefox-ext-beagle~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.9~40.5mdv2010.1", rls:"MNDK_2010.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

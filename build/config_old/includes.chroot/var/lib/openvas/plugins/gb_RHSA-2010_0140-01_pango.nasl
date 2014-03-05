###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pango RHSA-2010:0140-01
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
tag_insight = "Pango is a library used for the layout and rendering of internationalized
  text.

  An input sanitization flaw, leading to an array index error, was found in
  the way the Pango font rendering library synthesized the Glyph Definition
  (GDEF) table from a font's character map and the Unicode property database.
  If an attacker created a specially-crafted font file and tricked a local,
  unsuspecting user into loading the font file in an application that uses
  the Pango font rendering library, it could cause that application to crash.
  (CVE-2010-0421)
  
  Users of pango and evolution28-pango are advised to upgrade to these
  updated packages, which contain a backported patch to resolve this issue.
  After installing this update, you must restart your system or restart your
  X session for this update to take effect.";

tag_affected = "pango on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 3,
  Red Hat Enterprise Linux WS version 4";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00005.html");
  script_id(870232);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2010:0140-01");
  script_cve_id("CVE-2010-0421");
  script_name("RedHat Update for pango RHSA-2010:0140-01");

  script_description(desc);
  script_summary("Check for the Version of pango");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.14.9~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango-debuginfo", rpm:"pango-debuginfo~1.14.9~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.14.9~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"evolution28-pango", rpm:"evolution28-pango~1.14.9~13.el4_8", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution28-pango-debuginfo", rpm:"evolution28-pango-debuginfo~1.14.9~13.el4_8", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"evolution28-pango-devel", rpm:"evolution28-pango-devel~1.14.9~13.el4_8", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.6.0~16.el4_8", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango-debuginfo", rpm:"pango-debuginfo~1.6.0~16.el4_8", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.6.0~16.el4_8", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.2.5~10", rls:"RHENT_3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango-debuginfo", rpm:"pango-debuginfo~1.2.5~10", rls:"RHENT_3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.2.5~10", rls:"RHENT_3")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

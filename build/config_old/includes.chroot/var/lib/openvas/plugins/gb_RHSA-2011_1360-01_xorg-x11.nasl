###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xorg-x11 RHSA-2011:1360-01
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
tag_insight = "X.Org is an open source implementation of the X Window System. It provides
  the basic low-level functionality that full-fledged graphical user
  interfaces are designed upon.

  Multiple input sanitization flaws were found in the X.Org GLX (OpenGL
  extension to the X Window System) extension. A malicious, authorized client
  could use these flaws to crash the X.Org server or, potentially, execute
  arbitrary code with root privileges. (CVE-2010-4818)
  
  An input sanitization flaw was found in the X.Org Render extension. A
  malicious, authorized client could use this flaw to leak arbitrary memory
  from the X.Org server process, or possibly crash the X.Org server.
  (CVE-2010-4819)
  
  Users of xorg-x11 should upgrade to these updated packages, which contain a
  backported patch to resolve these issues. All running X.Org server
  instances must be restarted for this update to take effect.";

tag_affected = "xorg-x11 on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2011-October/msg00004.html");
  script_id(870499);
  script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-10 16:05:48 +0200 (Mon, 10 Oct 2011)");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "RHSA", value: "2011:1360-01");
  script_cve_id("CVE-2010-4818", "CVE-2010-4819");
  script_name("RedHat Update for xorg-x11 RHSA-2011:1360-01");

  script_description(desc);
  script_summary("Check for the Version of xorg-x11");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"xorg-x11", rpm:"xorg-x11~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Mesa-libGL", rpm:"xorg-x11-Mesa-libGL~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Mesa-libGLU", rpm:"xorg-x11-Mesa-libGLU~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xdmx", rpm:"xorg-x11-Xdmx~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xnest", rpm:"xorg-x11-Xnest~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-Xvfb", rpm:"xorg-x11-Xvfb~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-deprecated-libs", rpm:"xorg-x11-deprecated-libs~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-deprecated-libs-devel", rpm:"xorg-x11-deprecated-libs-devel~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-devel", rpm:"xorg-x11-devel~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-doc", rpm:"xorg-x11-doc~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-font-utils", rpm:"xorg-x11-font-utils~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-libs", rpm:"xorg-x11-libs~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-sdk", rpm:"xorg-x11-sdk~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-tools", rpm:"xorg-x11-tools~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-twm", rpm:"xorg-x11-twm~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xauth", rpm:"xorg-x11-xauth~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xdm", rpm:"xorg-x11-xdm~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-xfs", rpm:"xorg-x11-xfs~6.8.2~1.EL.70", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tcltk RHSA-2008:0134-01
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
tag_insight = "Tcl is a scripting language designed for embedding into other applications
  and for use with Tk, a widget set.

  An input validation flaw was discovered in Tk's GIF image handling. A
  code-size value read from a GIF image was not properly validated before
  being used, leading to a buffer overflow. A specially crafted GIF file
  could use this to cause a crash or, potentially, execute code with the
  privileges of the application using the Tk graphical toolkit.
  (CVE-2008-0553)
  
  A buffer overflow flaw was discovered in Tk's animated GIF image handling.
  An animated GIF containing an initial image smaller than subsequent images
  could cause a crash or, potentially, execute code with the privileges of
  the application using the Tk library. (CVE-2007-5378)
  
  A flaw in the Tcl regular expression handling engine was discovered by Will
  Drewry. This flaw, first discovered in the Tcl regular expression engine
  used in the PostgreSQL database server, resulted in an infinite loop when
  processing certain regular expressions. (CVE-2007-4772)
  
  All users are advised to upgrade to these updated packages which contain
  backported patches which resolve these issues.";

tag_affected = "tcltk on Red Hat Enterprise Linux AS (Advanced Server) version 2.1,
  Red Hat Enterprise Linux ES version 2.1,
  Red Hat Enterprise Linux WS version 2.1,
  Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-February/msg00008.html");
  script_id(870139);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2008:0134-01");
  script_cve_id("CVE-2008-0553", "CVE-2007-5378", "CVE-2007-4772");
  script_name( "RedHat Update for tcltk RHSA-2008:0134-01");

  script_description(desc);
  script_summary("Check for the Version of tcltk");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "RHENT_2.1")
{

  if ((res = isrpmvuln(pkg:"expect", rpm:"expect~5.38.0~75", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"itcl", rpm:"itcl~3.2~75", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl", rpm:"tcl~8.3.3~75", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcllib", rpm:"tcllib~1.0~75", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tclx", rpm:"tclx~8.3~75", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tix", rpm:"tix~8.2.0b1~75", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tk", rpm:"tk~8.3.3~75", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"expect", rpm:"expect~5.38.0~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"expect-devel", rpm:"expect-devel~5.38.0~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"itcl", rpm:"itcl~3.2~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl", rpm:"tcl~8.3.5~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcl-devel", rpm:"tcl-devel~8.3.5~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tcltk-debuginfo", rpm:"tcltk-debuginfo~8.3.5~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tclx", rpm:"tclx~8.3~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tix", rpm:"tix~8.1.4~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tk", rpm:"tk~8.3.5~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tk-devel", rpm:"tk-devel~8.3.5~92.8", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

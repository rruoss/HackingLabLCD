###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xorg-x11-server RHSA-2008:0504-01
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
tag_insight = "X.Org is an open source implementation of the X Window System. It provides
  basic low-level functionality that full-fledged graphical user interfaces
  are designed upon.

  An input validation flaw was discovered in X.org's Security and Record
  extensions. A malicious authorized client could exploit this issue to cause
  a denial of service (crash) or, potentially, execute arbitrary code with
  root privileges on the X.Org server. (CVE-2008-1377)
  
  Multiple integer overflow flaws were found in X.org's Render extension. A
  malicious authorized client could exploit these issues to cause a denial of
  service (crash) or, potentially, execute arbitrary code with root
  privileges on the X.Org server. (CVE-2008-2360, CVE-2008-2361,
  CVE-2008-2362)
  
  An input validation flaw was discovered in X.org's MIT-SHM extension. A
  client connected to the X.org server could read arbitrary server memory.
  This could result in the sensitive data of other users of the X.org server
  being disclosed. (CVE-2008-1379)
  
  Users of xorg-x11-server should upgrade to these updated packages, which
  contain backported patches to resolve these issues.";

tag_affected = "xorg-x11-server on Red Hat Enterprise Linux (v. 5 server)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-June/msg00010.html");
  script_id(870148);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "RHSA", value: "2008:0504-01");
  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
  script_name( "RedHat Update for xorg-x11-server RHSA-2008:0504-01");

  script_description(desc);
  script_summary("Check for the Version of xorg-x11-server");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-debuginfo", rpm:"xorg-x11-server-debuginfo~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-randr-source", rpm:"xorg-x11-server-randr-source~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.1.1~48.41.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
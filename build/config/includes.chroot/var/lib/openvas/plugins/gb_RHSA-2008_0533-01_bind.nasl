###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for bind RHSA-2008:0533-01
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
tag_insight = "ISC BIND (Berkeley Internet Name Domain) is an implementation of the DNS
  (Domain Name System) protocols.

  The DNS protocol protects against spoofing attacks by requiring an attacker
  to predict both the DNS transaction ID and UDP source port of a request. In
  recent years, a number of papers have found problems with DNS
  implementations which make it easier for an attacker to perform DNS
  cache-poisoning attacks.
  
  Previous versions of BIND did not use randomized UDP source ports. If an
  attacker was able to predict the random DNS transaction ID, this could make
  DNS cache-poisoning attacks easier. In order to provide more resilience,
  BIND has been updated to use a range of random UDP source ports.
  (CVE-2008-1447)
  
  Note: This errata also updates SELinux policy on Red Hat Enterprise Linux 4
  and 5 to allow BIND to use random UDP source ports.
  
  Users of BIND are advised to upgrade to these updated packages, which
  contain a backported patch to add this functionality.
  
  Red Hat would like to thank Dan Kaminsky for reporting this issue.";

tag_affected = "bind on Red Hat Enterprise Linux AS (Advanced Server) version 2.1,
  Red Hat Enterprise Linux ES version 2.1,
  Red Hat Enterprise Linux WS version 2.1,
  Red Hat Enterprise Linux AS version 3,
  Red Hat Enterprise Linux ES version 3,
  Red Hat Enterprise Linux WS version 3,
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4,
  Red Hat Enterprise Linux (v. 5 server)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00007.html");
  script_id(870051);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "RHSA", value: "2008:0533-01");
  script_cve_id("CVE-2008-1447");
  script_name( "RedHat Update for bind RHSA-2008:0533-01");

  script_description(desc);
  script_summary("Check for the Version of bind");
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

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.1~10.el2", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.1~10.el2", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.1~10.el2", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libbind-devel", rpm:"bind-libbind-devel~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"caching-nameserver", rpm:"caching-nameserver~9.3.4~6.0.1.P1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy", rpm:"selinux-policy~2.4.6~137.1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-devel", rpm:"selinux-policy-devel~2.4.6~137.1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-mls", rpm:"selinux-policy-mls~2.4.6~137.1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-strict", rpm:"selinux-policy-strict~2.4.6~137.1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-targeted", rpm:"selinux-policy-targeted~2.4.6~137.1.el5_2", rls:"RHENT_5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.4~28.0.1.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.2.4~28.0.1.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.2.4~28.0.1.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.4~28.0.1.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.2.4~28.0.1.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.4~28.0.1.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-targeted", rpm:"selinux-policy-targeted~1.17.30~2.150.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"selinux-policy-targeted-sources", rpm:"selinux-policy-targeted-sources~1.17.30~2.150.el4", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_3")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.2.4~22.el3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.2.4~22.el3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.2.4~22.el3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.2.4~22.el3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.2.4~22.el3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.2.4~22.el3", rls:"RHENT_3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
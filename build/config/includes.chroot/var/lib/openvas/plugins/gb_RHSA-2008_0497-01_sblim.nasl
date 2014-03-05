###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for sblim RHSA-2008:0497-01
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
tag_insight = "SBLIM stands for Standards-Based Linux Instrumentation for Manageability.
  It consists of a set of standards-based, Web-Based Enterprise Management
  (WBEM) modules that use the Common Information Model (CIM) standard to
  gather and provide systems management information, events, and methods to
  local or networked consumers via a CIM object services broker using the
  CMPI (Common Manageability Programming Interface) standard. This package
  provides a set of core providers and development tools for systems
  management applications.

  It was discovered that certain sblim libraries had an RPATH (runtime
  library search path) set in the ELF (Executable and Linking Format) header.
  This RPATH pointed to a sub-directory of a world-writable, temporary
  directory. A local user could create a file with the same name as a library
  required by sblim (such as libc.so) and place it in the directory defined
  in the RPATH. This file could then execute arbitrary code with the
  privileges of the user running an application that used sblim (eg
  tog-pegasus). (CVE-2008-1951)
  
  Users are advised to upgrade to these updated sblim packages, which resolve
  this issue.";

tag_affected = "sblim on Red Hat Enterprise Linux AS version 4,
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-June/msg00019.html");
  script_id(870135);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2008:0497-01");
  script_cve_id("CVE-2008-1951");
  script_name( "RedHat Update for sblim RHSA-2008:0497-01");

  script_description(desc);
  script_summary("Check for the Version of sblim");
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

  if ((res = isrpmvuln(pkg:"sblim-cim-client", rpm:"sblim-cim-client~1.3.3~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cim-client-javadoc-1-31.el5", rpm:"sblim-cim-client-javadoc-1-31.el5~2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cim-client-manual-1-31.el5", rpm:"sblim-cim-client-manual-1-31.el5~2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-base", rpm:"sblim-cmpi-base~1.5.5~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-base-devel", rpm:"sblim-cmpi-base-devel~1.5.5~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-base-test", rpm:"sblim-cmpi-base-test~1.5.5~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-devel", rpm:"sblim-cmpi-devel~1.0.4~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-dns", rpm:"sblim-cmpi-dns~0.5.2~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-dns-devel-1-31.el5", rpm:"sblim-cmpi-dns-devel-1-31.el5~2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-dns-test-1-31.el5", rpm:"sblim-cmpi-dns-test-1-31.el5~2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol", rpm:"sblim-cmpi-fsvol~1.4.4~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol-devel", rpm:"sblim-cmpi-fsvol-devel~1.4.4~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol-test", rpm:"sblim-cmpi-fsvol-test~1.4.4~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-network", rpm:"sblim-cmpi-network~1.3.8~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-network-devel", rpm:"sblim-cmpi-network-devel~1.3.8~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-network-test", rpm:"sblim-cmpi-network-test~1.3.8~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv3", rpm:"sblim-cmpi-nfsv3~1.0.14~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv3-test", rpm:"sblim-cmpi-nfsv3-test~1.0.14~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv4", rpm:"sblim-cmpi-nfsv4~1.0.12~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv4-test", rpm:"sblim-cmpi-nfsv4-test~1.0.12~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-params", rpm:"sblim-cmpi-params~1.2.6~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-params-test", rpm:"sblim-cmpi-params-test~1.2.6~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-samba", rpm:"sblim-cmpi-samba~0.5.2~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-samba-devel-1-31.el5", rpm:"sblim-cmpi-samba-devel-1-31.el5~2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-samba-test-1-31.el5", rpm:"sblim-cmpi-samba-test-1-31.el5~2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-sysfs", rpm:"sblim-cmpi-sysfs~1.1.9~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-sysfs-test", rpm:"sblim-cmpi-sysfs-test~1.1.9~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-syslog", rpm:"sblim-cmpi-syslog~0.7.11~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-syslog-test", rpm:"sblim-cmpi-syslog-test~0.7.11~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-debuginfo-1-31.el5", rpm:"sblim-debuginfo-1-31.el5~2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather", rpm:"sblim-gather~2.1.2~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather-devel", rpm:"sblim-gather-devel~2.1.2~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather-provider", rpm:"sblim-gather-provider~2.1.2~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather-test", rpm:"sblim-gather-test~2.1.2~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-testsuite", rpm:"sblim-testsuite~1.2.4~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-tools-libra", rpm:"sblim-tools-libra~0.2.3~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-tools-libra-devel", rpm:"sblim-tools-libra-devel~0.2.3~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-wbemcli", rpm:"sblim-wbemcli~1.5.1~31.el5_2.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"sblim-cmpi-base", rpm:"sblim-cmpi-base~1.5.4~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-base-devel", rpm:"sblim-cmpi-base-devel~1.5.4~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-base-test", rpm:"sblim-cmpi-base-test~1.5.4~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-devel", rpm:"sblim-cmpi-devel~1.0.4~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol", rpm:"sblim-cmpi-fsvol~1.4.3~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol-devel", rpm:"sblim-cmpi-fsvol-devel~1.4.3~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-fsvol-test", rpm:"sblim-cmpi-fsvol-test~1.4.3~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-network", rpm:"sblim-cmpi-network~1.3.7~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-network-devel", rpm:"sblim-cmpi-network-devel~1.3.7~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-network-test", rpm:"sblim-cmpi-network-test~1.3.7~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv3", rpm:"sblim-cmpi-nfsv3~1.0.13~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv3-test", rpm:"sblim-cmpi-nfsv3-test~1.0.13~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv4", rpm:"sblim-cmpi-nfsv4~1.0.11~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-nfsv4-test", rpm:"sblim-cmpi-nfsv4-test~1.0.11~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-params", rpm:"sblim-cmpi-params~1.2.4~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-params-test", rpm:"sblim-cmpi-params-test~1.2.4~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-sysfs", rpm:"sblim-cmpi-sysfs~1.1.8~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-sysfs-test", rpm:"sblim-cmpi-sysfs-test~1.1.8~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-syslog", rpm:"sblim-cmpi-syslog~0.7.9~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-cmpi-syslog-test", rpm:"sblim-cmpi-syslog-test~0.7.9~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-debuginfo-1-13a.el4", rpm:"sblim-debuginfo-1-13a.el4~6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather", rpm:"sblim-gather~2.1.1~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather-devel", rpm:"sblim-gather-devel~2.1.1~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather-provider", rpm:"sblim-gather-provider~2.1.1~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-gather-test", rpm:"sblim-gather-test~2.1.1~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-testsuite", rpm:"sblim-testsuite~1.2.4~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sblim-wbemcli", rpm:"sblim-wbemcli~1.5.1~13a.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

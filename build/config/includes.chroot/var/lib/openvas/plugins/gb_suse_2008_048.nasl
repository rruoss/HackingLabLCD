###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2008:048
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
tag_insight = "This kernel security update for SUSE Linux Enterprise 10 Service Pack
  2 fixes lots of bugs and some security issues:

  CVE-2008-0598: Fixed an information leak in the x86_64 version of
  the string copy routines.

  CVE-2008-1673: Fixed range checking in previous ASN.1 fixes for CIFS
  and SNMP NAT netfilter module.

  CVE-2008-3272: Fixed range checking in the snd_seq OSS ioctl, which
  could be used to leak information from the kernel.

  CVE-2008-3275: Fixed a memory leak when looking up deleted directories
  which could be used to run the system out of memory.

  The full amount of changes can be reviewed in the RPM changelog.";

tag_impact = "remote denial of service";
tag_affected = "kernel on SLE SDK 10 SP2, SUSE Linux Enterprise Desktop 10 SP2, SUSE Linux Enterprise 10 SP2 DEBUGINFO, SUSE Linux Enterprise Server 10 SP2";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2008_48_kernel.html");
  script_id(850019);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:44:26 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2008-048");
  script_cve_id("CVE-2008-0598", "CVE-2008-1673", "CVE-2008-3272", "CVE-2008-3275");
  script_name( "SuSE Update for kernel SUSE-SA:2008:048");

  script_description(desc);
  script_summary("Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
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

if(release == "LES10SP2")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.30", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.30", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.30", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.30", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.30", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.29", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.29", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.29", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.29", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.29", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.29", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.29", rls:"LES10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDK10SP2")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.30", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.30", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.30", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.30", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.30", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.29", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.29", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.29", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.29", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.29", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.29", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.29", rls:"SLESDK10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP2")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.30", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.30", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.30", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.30", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.30", rls:"SLESDk10SP2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

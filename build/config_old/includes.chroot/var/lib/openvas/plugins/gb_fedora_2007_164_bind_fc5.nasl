###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for bind FEDORA-2007-164
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
tag_affected = "bind on Fedora Core 5";
tag_insight = "BIND (Berkeley Internet Name Domain) is an implementation of the DNS
  (Domain Name System) protocols. BIND includes a DNS server (named),
  which resolves host names to IP addresses; a resolver library
  (routines for applications to use when interfacing with DNS); and
  tools for verifying that the DNS server is operating properly.";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-January/msg00180.html");
  script_id(861148);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 15:48:41 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2007-164");
  script_cve_id("CVE-2006-4095");
  script_name( "Fedora Update for bind FEDORA-2007-164");

  script_description(desc);
  script_summary("Check for the Version of bind");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora_core", "login/SSH/success", "ssh/login/release");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"bind", rpm:"bind~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bind-devel", rpm:"x86_64/bind-devel~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/bind-debuginfo", rpm:"x86_64/debug/bind-debuginfo~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bind-libs", rpm:"x86_64/bind-libs~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bind-sdb", rpm:"x86_64/bind-sdb~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bind-libbind-devel", rpm:"x86_64/bind-libbind-devel~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bind-chroot", rpm:"x86_64/bind-chroot~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bind-utils", rpm:"x86_64/bind-utils~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/bind", rpm:"x86_64/bind~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/caching-nameserver", rpm:"x86_64/caching-nameserver~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bind-devel", rpm:"i386/bind-devel~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bind-libbind-devel", rpm:"i386/bind-libbind-devel~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bind-chroot", rpm:"i386/bind-chroot~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/bind-debuginfo", rpm:"i386/debug/bind-debuginfo~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bind", rpm:"i386/bind~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bind-utils", rpm:"i386/bind-utils~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/caching-nameserver", rpm:"i386/caching-nameserver~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bind-sdb", rpm:"i386/bind-sdb~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/bind-libs", rpm:"i386/bind-libs~9.3.4~1.fc5", rls:"FC5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for openssh FEDORA-2007-395
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
tag_insight = "SSH (Secure SHell) is a program for logging into and executing
  commands on a remote machine. SSH is intended to replace rlogin and
  rsh, and to provide secure encrypted communications between two
  untrusted hosts over an insecure network. X11 connections and
  arbitrary TCP/IP ports can also be forwarded over the secure channel.

  OpenSSH is OpenBSD's version of the last free version of SSH, bringing
  it up to date in terms of security and features, as well as removing
  all patented algorithms to separate libraries.
  
  This package includes the core files necessary for both the OpenSSH
  client and server. To make this package useful, you should also
  install openssh-clients, openssh-server, or both";

tag_affected = "openssh on Fedora Core 5";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-April/msg00011.html");
  script_id(861319);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:23:18 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "FEDORA", value: "2007-395");
  script_cve_id("CVE-2006-5052", "CVE-2006-5794", "CVE-2006-4924", "CVE-2006-5051");
  script_name( "Fedora Update for openssh FEDORA-2007-395");

  script_description(desc);
  script_summary("Check for the Version of openssh");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora_core", "login/SSH/success", "ssh/login/release");
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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/openssh", rpm:"x86_64/openssh~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/openssh-server", rpm:"x86_64/openssh-server~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/openssh-clients", rpm:"x86_64/openssh-clients~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/openssh-askpass", rpm:"x86_64/openssh-askpass~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/openssh-debuginfo", rpm:"x86_64/debug/openssh-debuginfo~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openssh-server", rpm:"i386/openssh-server~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openssh-askpass", rpm:"i386/openssh-askpass~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openssh-clients", rpm:"i386/openssh-clients~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/openssh-debuginfo", rpm:"i386/debug/openssh-debuginfo~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/openssh", rpm:"i386/openssh~4.3p2~4.12.fc5", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

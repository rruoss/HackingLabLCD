###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for gnupg FEDORA-2007-316
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
tag_affected = "gnupg on Fedora Core 5";
tag_insight = "GnuPG (GNU Privacy Guard) is a GNU utility for encrypting data and
  creating digital signatures. GnuPG has advanced key management
  capabilities and is compliant with the proposed OpenPGP Internet
  standard described in RFC2440. Since GnuPG doesn't use any patented
  algorithm, it is not compatible with any version of PGP2 (PGP2.x uses
  only IDEA for symmetric-key encryption, which is patented worldwide).";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-March/msg00032.html");
  script_id(861323);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:23:18 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "FEDORA", value: "2007-316");
  script_cve_id("CVE-2006-6169", "CVE-2006-6235", "CVE-2006-3746", "CVE-2006-3082");
  script_name( "Fedora Update for gnupg FEDORA-2007-316");

  script_description(desc);
  script_summary("Check for the Version of gnupg");
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

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.7~1", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/gnupg", rpm:"x86_64/gnupg~1.4.7~1", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/gnupg-debuginfo", rpm:"x86_64/debug/gnupg-debuginfo~1.4.7~1", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/gnupg-debuginfo", rpm:"i386/debug/gnupg-debuginfo~1.4.7~1", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/gnupg", rpm:"i386/gnupg~1.4.7~1", rls:"FC5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
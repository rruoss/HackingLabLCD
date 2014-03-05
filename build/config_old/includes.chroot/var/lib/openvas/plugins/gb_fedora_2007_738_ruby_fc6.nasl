###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ruby FEDORA-2007-738
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
tag_affected = "ruby on Fedora Core 6";
tag_insight = "Ruby is the interpreted scripting language for quick and easy
  object-oriented programming.  It has many features to process text
  files and to do system management tasks (as in Perl).  It is simple,
  straight-forward, and extensible.";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-November/msg00076.html");
  script_id(861063);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:31:39 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2007-738");
  script_cve_id("CVE-2007-5162");
  script_name( "Fedora Update for ruby FEDORA-2007-738");

  script_description(desc);
  script_summary("Check for the Version of ruby");
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

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-docs", rpm:"x86_64/ruby-docs~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-rdoc", rpm:"x86_64/ruby-rdoc~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-irb", rpm:"x86_64/ruby-irb~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby", rpm:"x86_64/ruby~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-tcltk", rpm:"x86_64/ruby-tcltk~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-mode", rpm:"x86_64/ruby-mode~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/ruby-debuginfo", rpm:"x86_64/debug/ruby-debuginfo~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-ri", rpm:"x86_64/ruby-ri~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-devel", rpm:"x86_64/ruby-devel~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ruby-libs", rpm:"x86_64/ruby-libs~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-rdoc", rpm:"i386/ruby-rdoc~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/ruby-debuginfo", rpm:"i386/debug/ruby-debuginfo~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-ri", rpm:"i386/ruby-ri~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-docs", rpm:"i386/ruby-docs~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby", rpm:"i386/ruby~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-tcltk", rpm:"i386/ruby-tcltk~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-libs", rpm:"i386/ruby-libs~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-mode", rpm:"i386/ruby-mode~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-devel", rpm:"i386/ruby-devel~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ruby-irb", rpm:"i386/ruby-irb~1.8.5.114~1.fc6", rls:"FC6")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
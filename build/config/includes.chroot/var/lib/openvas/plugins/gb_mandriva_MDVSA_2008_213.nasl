###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for dbus MDVSA-2008:213 (dbus)
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
tag_insight = "The D-Bus library did not correctly validate certain corrupted
  signatures which could cause a crash of applications linked against
  the D-Bus library if a local user were to send a specially crafted
  D-Bus request (CVE-2008-3834).

  The updated packages have been patched to prevent this issue.";

tag_affected = "dbus on Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64,
  Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64,
  Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-10/msg00021.php");
  script_id(830423);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVSA", value: "2008:213");
  script_cve_id("CVE-2008-3834");
  script_name( "Mandriva Update for dbus MDVSA-2008:213 (dbus)");

  script_description(desc);
  script_summary("Check for the Version of dbus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
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

if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.0.2~10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.0.2~10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdbus-1_3", rpm:"libdbus-1_3~1.0.2~10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdbus-1_3-devel", rpm:"libdbus-1_3-devel~1.0.2~10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64dbus-1_3", rpm:"lib64dbus-1_3~1.0.2~10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64dbus-1_3-devel", rpm:"lib64dbus-1_3-devel~1.0.2~10.3mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.1.20~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.1.20~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdbus-1_3", rpm:"libdbus-1_3~1.1.20~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdbus-1-devel", rpm:"libdbus-1-devel~1.1.20~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64dbus-1_3", rpm:"lib64dbus-1_3~1.1.20~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64dbus-1-devel", rpm:"lib64dbus-1-devel~1.1.20~5.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"dbus", rpm:"dbus~1.2.3~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dbus-x11", rpm:"dbus-x11~1.2.3~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdbus-1_3", rpm:"libdbus-1_3~1.2.3~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libdbus-1-devel", rpm:"libdbus-1-devel~1.2.3~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64dbus-1_3", rpm:"lib64dbus-1_3~1.2.3~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64dbus-1-devel", rpm:"lib64dbus-1-devel~1.2.3~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

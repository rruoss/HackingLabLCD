###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for gnupg MDKSA-2007:059 (gnupg)
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
tag_insight = "GnuPG prior to 1.4.7 and GPGME prior to 1.1.4, when run from the
  command
  line, did not visually distinguish signed and unsigned portions of
  OpenPGP messages with multiple components.  This could allow a remote
  attacker to forge the contents of an email message without detection.

  GnuPG 1.4.7 is being provided with this update and GPGME has been
  patched on Mandriva 2007.0 to provide better visual notification on
  these types of forgeries.";

tag_affected = "gnupg on Mandriva Linux 2006.0,
  Mandriva Linux 2006.0/X86_64,
  Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-03/msg00011.php");
  script_id(830318);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:53:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDKSA", value: "2007:059");
  script_cve_id("CVE-2007-1263");
  script_name( "Mandriva Update for gnupg MDKSA-2007:059 (gnupg)");

  script_description(desc);
  script_summary("Check for the Version of gnupg");
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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.7~0.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgpgme11", rpm:"libgpgme11~1.1.2~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgpgme11-devel", rpm:"libgpgme11-devel~1.1.2~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gpgme", rpm:"gpgme~1.1.2~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gpgme11", rpm:"lib64gpgme11~1.1.2~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64gpgme11-devel", rpm:"lib64gpgme11-devel~1.1.2~2.1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2006.0")
{

  if ((res = isrpmvuln(pkg:"gnupg", rpm:"gnupg~1.4.7~0.2.20060mdk", rls:"MNDK_2006.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

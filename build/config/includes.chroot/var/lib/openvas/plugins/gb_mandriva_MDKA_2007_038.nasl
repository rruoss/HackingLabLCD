###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for mandriva-theme MDKA-2007:038 (mandriva-theme)
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
tag_affected = "mandriva-theme on Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_insight = "Some background images were not consistent with the final 2007
  Spring theme.  This update package fixes the Mandriva-1440x900 and
  Mandriva-Powerpack+-1280x800 background images.";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-05/msg00016.php");
  script_id(830142);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:48:43 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDKA", value: "2007:038");
  script_name( "Mandriva Update for mandriva-theme MDKA-2007:038 (mandriva-theme)");

  script_description(desc);
  script_summary("Check for the Version of mandriva-theme");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"mandriva-theme", rpm:"mandriva-theme~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Discovery", rpm:"mandriva-theme-Discovery~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Discovery-screensaver", rpm:"mandriva-theme-Discovery-screensaver~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Flash", rpm:"mandriva-theme-Flash~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Flash-screensaver", rpm:"mandriva-theme-Flash-screensaver~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-One", rpm:"mandriva-theme-One~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-One-screensaver", rpm:"mandriva-theme-One-screensaver~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Powerpack+", rpm:"mandriva-theme-Powerpack+~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Powerpack+-screensaver", rpm:"mandriva-theme-Powerpack+-screensaver~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Powerpack", rpm:"mandriva-theme-Powerpack~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-Powerpack-screensaver", rpm:"mandriva-theme-Powerpack-screensaver~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-common", rpm:"mandriva-theme-common~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mandriva-theme-screensaver", rpm:"mandriva-theme-screensaver~1.2.11~1.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

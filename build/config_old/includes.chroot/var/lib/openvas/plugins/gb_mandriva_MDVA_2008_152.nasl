###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for totem-pl-parser MDVA-2008:152 (totem-pl-parser)
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
tag_affected = "totem-pl-parser on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";
tag_insight = "The totem playlist parser library was not exporting a symbol required
  by the python binding.  This update adds the symbol and fixes several
  other bugs.";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-10/msg00032.php");
  script_id(830455);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:09:08 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVA", value: "2008:152");
  script_name( "Mandriva Update for totem-pl-parser MDVA-2008:152 (totem-pl-parser)");

  script_description(desc);
  script_summary("Check for the Version of totem-pl-parser");
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

if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"libtotem-plparser12", rpm:"libtotem-plparser12~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtotem-plparser-devel", rpm:"libtotem-plparser-devel~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtotem-plparser-mini12", rpm:"libtotem-plparser-mini12~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-pl-parser-i18n", rpm:"totem-pl-parser-i18n~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"totem-pl-parser", rpm:"totem-pl-parser~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64totem-plparser12", rpm:"lib64totem-plparser12~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64totem-plparser-devel", rpm:"lib64totem-plparser-devel~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64totem-plparser-mini12", rpm:"lib64totem-plparser-mini12~2.24.1~2.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for OpenOffice_org SUSE-SA:2007:037
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
tag_insight = "The Office suite OpenOffice_org was updated to fix a heap buffer
  overflow in its RTF parser.

  This issue could be used by attackers sending specially crafted RTF
  files to potentially execute code and it is tracked by the Mitre CVE
  ID CVE-2007-0245.

  Packages for SUSE Linux 10.0, SUSE Linux 10.1 and openSUSE 10.2 on
  June 20th, for SUSE Linux Desktop 1.0 and Novell Linux Desktop on
  June 15th, for SUSE Linux Enterprise Desktop 10 on June 28th.

  For SUSE Linux Enterprise 10 additional non-security bugs were fixed.";

tag_impact = "remote code execution";
tag_affected = "OpenOffice_org on SUSE LINUX 10.1, openSUSE 10.2, Novell Linux Desktop 9, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1";
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
  script_xref(name : "URL" , value : "http://www.novell.com/linux/security/advisories/2007_37_openoffice.html");
  script_id(850106);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "SUSE-SA", value: "2007-037");
  script_cve_id("CVE-2007-0245");
  script_name( "SuSE Update for OpenOffice_org SUSE-SA:2007:037");

  script_description(desc);
  script_summary("Check for the Version of OpenOffice_org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "HostDetails/OS/cpe:/o:suse:linux_enterprise_server", "ssh/login/release");
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

if(release == "SLESDK10SP1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.1~0.26", rls:"SLESDK10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "openSUSE10.2")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-af", rpm:"OpenOffice_org-af~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gu-IN", rpm:"OpenOffice_org-gu-IN~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hi-IN", rpm:"OpenOffice_org-hi-IN~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nb", rpm:"OpenOffice_org-nb~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nn", rpm:"OpenOffice_org-nn~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-xh", rpm:"OpenOffice_org-xh~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zu", rpm:"OpenOffice_org-zu~2.0.4~38.5", rls:"openSUSE10.2")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "NLDk9")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-el", rpm:"OpenOffice_org-el~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en", rpm:"OpenOffice_org-en~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-et", rpm:"OpenOffice_org-et~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ko", rpm:"OpenOffice_org-ko~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt", rpm:"OpenOffice_org-pt~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sl", rpm:"OpenOffice_org-sl~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-tr", rpm:"OpenOffice_org-tr~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~1.1.5~0.18", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~1.1~110", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~1.1~110", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~1.1~110", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-en", rpm:"OpenOffice_org-en~1.1~110", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~1.1~110", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~1.1~110", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~1.1~110", rls:"NLDk9")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.1~0.26", rls:"SLESDk10SP1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"OpenOffice_org", rpm:"OpenOffice_org~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-af", rpm:"OpenOffice_org-af~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ar", rpm:"OpenOffice_org-ar~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ca", rpm:"OpenOffice_org-ca~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-cs", rpm:"OpenOffice_org-cs~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-da", rpm:"OpenOffice_org-da~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de", rpm:"OpenOffice_org-de~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-de-templates", rpm:"OpenOffice_org-de-templates~8.2~171.3", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-es", rpm:"OpenOffice_org-es~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fi", rpm:"OpenOffice_org-fi~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-fr", rpm:"OpenOffice_org-fr~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-galleries", rpm:"OpenOffice_org-galleries~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gnome", rpm:"OpenOffice_org-gnome~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-gu-IN", rpm:"OpenOffice_org-gu-IN~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hi-IN", rpm:"OpenOffice_org-hi-IN~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-hu", rpm:"OpenOffice_org-hu~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-it", rpm:"OpenOffice_org-it~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ja", rpm:"OpenOffice_org-ja~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-kde", rpm:"OpenOffice_org-kde~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-mono", rpm:"OpenOffice_org-mono~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nb", rpm:"OpenOffice_org-nb~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nl", rpm:"OpenOffice_org-nl~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-nn", rpm:"OpenOffice_org-nn~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-officebean", rpm:"OpenOffice_org-officebean~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pl", rpm:"OpenOffice_org-pl~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-pt-BR", rpm:"OpenOffice_org-pt-BR~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-ru", rpm:"OpenOffice_org-ru~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sk", rpm:"OpenOffice_org-sk~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-sv", rpm:"OpenOffice_org-sv~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-xh", rpm:"OpenOffice_org-xh~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-CN", rpm:"OpenOffice_org-zh-CN~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zh-TW", rpm:"OpenOffice_org-zh-TW~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"OpenOffice_org-zu", rpm:"OpenOffice_org-zu~2.0.4~38.2.5", rls:"SL10.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

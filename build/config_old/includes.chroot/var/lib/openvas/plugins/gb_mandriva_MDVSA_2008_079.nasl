###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for sarg MDVSA-2008:079 (sarg)
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
tag_insight = "A stack-based buffer overflow in sarg (Squid Analysis Report Generator)
  allowed remote attackers to execute arbitrary code via a long Squid
  proxy server User-Agent header (CVE-2008-1167).

  A cross-site scripting vulnerability in sarg version 2.x prior to
  2.2.5 allowed remote attackers to inject arbitrary web script or
  HTML via the User-Agent heder, which is not properly handled when
  displaying the Squid proxy log (CVE-2008-1168).
  
  In addition, a number of other fixes have been made such as making
  the getword() function more robust which should prevent any overflows,
  other segfaults have been fixed, and the useragent report is now more
  consistent with the other reports.
  
  The updated packages have been patched to correct these issues.";

tag_affected = "sarg on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64,
  Mandriva Linux 2008.0,
  Mandriva Linux 2008.0/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-03/msg00032.php");
  script_id(830387);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2008:079");
  script_cve_id("CVE-2008-1167", "CVE-2008-1168");
  script_name( "Mandriva Update for sarg MDVSA-2008:079 (sarg)");

  script_description(desc);
  script_summary("Check for the Version of sarg");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"sarg", rpm:"sarg~2.2.5~0.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"sarg", rpm:"sarg~2.2.5~0.2mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2008.0")
{

  if ((res = isrpmvuln(pkg:"sarg", rpm:"sarg~2.2.5~0.2mdv2008.0", rls:"MNDK_2008.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

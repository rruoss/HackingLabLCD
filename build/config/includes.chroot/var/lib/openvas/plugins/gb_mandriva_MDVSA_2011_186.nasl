###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for nfs-utils MDVSA-2011:186 (nfs-utils)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "A vulnerability has been discovered and corrected in nfs-utils
  It was found that the mount.nfs tool did not handle certain errors
  correctly when updating the mtab (mounted file systems table)
  file. A local attacker could use this flaw to corrupt the mtab file
  (CVE-2011-1749).

  The updated packages have been patched to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "nfs-utils on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-12/msg00008.php");
  script_id(831505);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-16 11:12:38 +0530 (Fri, 16 Dec 2011)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVSA", value: "2011:186");
  script_cve_id("CVE-2011-1749");
  script_name("Mandriva Update for nfs-utils MDVSA-2011:186 (nfs-utils)");

  script_description(desc);
  script_summary("Check for the Version of nfs-utils");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.1.3~10.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nfs-utils-clients", rpm:"nfs-utils-clients~1.1.3~10.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.2.2~5.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nfs-utils-clients", rpm:"nfs-utils-clients~1.2.2~5.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

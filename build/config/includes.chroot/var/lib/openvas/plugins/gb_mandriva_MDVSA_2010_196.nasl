###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for dovecot MDVSA-2010:196 (dovecot)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "A vulnerability was discovered and corrected in dovecot:

  Multiple stack-based buffer overflows in the Sieve plugin in Dovecot
  1.0 before 1.0.4 and 1.1 before 1.1.7, as derived from Cyrus libsieve,
  allow context-dependent attackers to cause a denial of service
  (crash) and possibly execute arbitrary code via a crafted SIEVE
  script, as demonstrated by forwarding an e-mail message to a large
  number of recipients, a different vulnerability than CVE-2009-2632
  (CVE-2009-3235).
  
  Packages for 2009.1 were missing with the previous MDVSA-2009:242
  update. This update corrects this.
  
  This update provides a solution to this vulnerability.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "dovecot on Mandriva Linux 2009.1,
  Mandriva Linux 2009.1/X86_64";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-10/msg00008.php");
  script_id(831197);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-19 15:54:15 +0200 (Tue, 19 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVSA", value: "2010:196");
  script_cve_id("CVE-2009-2632", "CVE-2009-3235");
  script_name("Mandriva Update for dovecot MDVSA-2010:196 (dovecot)");

  script_description(desc);
  script_summary("Check for the Version of dovecot");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(release == "MNDK_2009.1")
{

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~1.1.13~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~1.1.13~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~1.1.13~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~1.1.13~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

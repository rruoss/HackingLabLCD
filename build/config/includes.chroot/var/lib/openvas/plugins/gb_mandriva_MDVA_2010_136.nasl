###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for php-pear-MDB2 MDVA-2010:136 (php-pear-MDB2)
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
tag_insight = "This new release fixes various issues in the PHP Pear MDB2 modules:

  - Can't save any identity (mdb2 problem)
  - When editing identities inside roundcube's preferences panel (ie:
  to change my display name), saving always return the error SERVICE
  CURRENTLY NOT AVAILABLE! Error No. [0x01F4]
  -  _skipDelimitedStrings() fails on empty strings";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "php-pear-MDB2 on Mandriva Enterprise Server 5,
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2010-04/msg00049.php");
  script_id(831016);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-30 14:39:22 +0200 (Fri, 30 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5"); 
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDVA", value: "2010:136");
  script_name("Mandriva Update for php-pear-MDB2 MDVA-2010:136 (php-pear-MDB2)");

  script_description(desc);
  script_summary("Check for the Version of php-pear-MDB2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "ssh/login/release");
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

  if ((res = isrpmvuln(pkg:"php-pear-MDB2", rpm:"php-pear-MDB2~2.5.0b2~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2_Driver_mysqli", rpm:"php-pear-MDB2_Driver_mysqli~1.5.0b2~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2_Driver_pgsql", rpm:"php-pear-MDB2_Driver_pgsql~1.5.0b2~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pear-MDB2_Driver_sqlite", rpm:"php-pear-MDB2_Driver_sqlite~1.5.0b2~1.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

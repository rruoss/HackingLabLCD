###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for openldap RHSA-2010:0542-01
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
tag_insight = "OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
  Protocol) applications and development tools.

  Multiple flaws were discovered in the way the slapd daemon handled modify
  relative distinguished name (modrdn) requests. An authenticated user with
  privileges to perform modrdn operations could use these flaws to crash the
  slapd daemon via specially-crafted modrdn requests. (CVE-2010-0211,
  CVE-2010-0212)
  
  Red Hat would like to thank CERT-FI for responsibly reporting these flaws,
  who credit Ilkka Mattila and Tuomas Salomki for the discovery of the
  issues.
  
  Users of OpenLDAP should upgrade to these updated packages, which contain
  a backported patch to correct these issues. After installing this update,
  the OpenLDAP daemons will be restarted automatically.";

tag_affected = "openldap on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-July/msg00009.html");
  script_id(870295);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-23 16:10:25 +0200 (Fri, 23 Jul 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2010:0542-01");
  script_cve_id("CVE-2010-0211", "CVE-2010-0212");
  script_name("RedHat Update for openldap RHSA-2010:0542-01");

  script_description(desc);
  script_summary("Check for the Version of openldap");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.3.43_2.2.29~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.3.43~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.3.43~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-debuginfo", rpm:"openldap-debuginfo~2.3.43~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.3.43~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.3.43~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-overlays", rpm:"openldap-servers-overlays~2.3.43~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.3.43~12.el5_5.1", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

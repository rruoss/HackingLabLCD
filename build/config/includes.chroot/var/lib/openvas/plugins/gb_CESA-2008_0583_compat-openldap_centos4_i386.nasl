###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for compat-openldap CESA-2008:0583 centos4 i386
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
tag_insight = "OpenLDAP is an open source suite of Lightweight Directory Access Protocol
  (LDAP) applications and development tools. LDAP is a set of protocols for
  accessing directory services.

  A denial of service flaw was found in the way the OpenLDAP slapd daemon
  processed certain network messages. An unauthenticated remote attacker
  could send a specially crafted request that would crash the slapd daemon.
  (CVE-2008-2952)
  
  Users of openldap should upgrade to these updated packages, which contain a
  backported patch to correct this issue.";

tag_affected = "compat-openldap on CentOS 4";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-July/015108.html");
  script_id(880026);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:40:14 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "CESA", value: "2008:0583");
  script_cve_id("CVE-2008-2952");
  script_name( "CentOS Update for compat-openldap CESA-2008:0583 centos4 i386");

  script_description(desc);
  script_summary("Check for the Version of compat-openldap");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.1.30~8.el4_6.5", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.2.13~8.el4_6.5", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.2.13~8.el4_6.5", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.2.13~8.el4_6.5", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.2.13~8.el4_6.5", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.2.13~8.el4_6.5", rls:"CentOS4")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

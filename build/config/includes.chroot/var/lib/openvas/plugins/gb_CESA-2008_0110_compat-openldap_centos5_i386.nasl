###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for compat-openldap CESA-2008:0110 centos5 i386
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

  These updated openldap packages fix a flaw in the way the OpenLDAP slapd
  daemon handled modify and modrdn requests with NOOP control on objects
  stored in a Berkeley DB (BDB) storage backend.  An authenticated attacker
  with permission to perform modify or modrdn operations on such LDAP objects
  could cause slapd to crash. (CVE-2007-6698, CVE-2008-0658)
  
  Users of openldap should upgrade to these updated packages, which contain a
  backported patch to correct this issue.";

tag_affected = "compat-openldap on CentOS 5";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-February/014702.html");
  script_id(880167);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "CESA", value: "2008:0110");
  script_cve_id("CVE-2007-6698", "CVE-2008-0658");
  script_name( "CentOS Update for compat-openldap CESA-2008:0110 centos5 i386");

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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"compat-openldap", rpm:"compat-openldap~2.3.27_2.2.29~8.el5_1.3", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.3.27~8.el5_1.3", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.3.27~8.el5_1.3", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.3.27~8.el5_1.3", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.3.27~8.el5_1.3", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.3.27~8.el5_1.3", rls:"CentOS5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

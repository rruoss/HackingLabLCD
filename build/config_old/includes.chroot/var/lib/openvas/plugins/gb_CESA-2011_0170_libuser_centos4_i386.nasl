###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libuser CESA-2011:0170 centos4 i386
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
tag_insight = "The libuser library implements a standardized interface for manipulating
  and administering user and group accounts. Sample applications that are
  modeled after applications from the shadow password suite (shadow-utils)
  are included in these packages.

  It was discovered that libuser did not set the password entry correctly
  when creating LDAP (Lightweight Directory Access Protocol) users. If an
  administrator did not assign a password to an LDAP based user account,
  either at account creation with luseradd, or with lpasswd after account
  creation, an attacker could use this flaw to log into that account with a
  default password string that should have been rejected. (CVE-2011-0002)
  
  Note: LDAP administrators that have used libuser tools to add users should
  check existing user accounts for plain text passwords, and reset them as
  necessary.
  
  Users of libuser should upgrade to these updated packages, which contain a
  backported patch to correct this issue.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "libuser on CentOS 4";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-February/017247.html");
  script_id(880470);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2011:0170");
  script_cve_id("CVE-2011-0002");
  script_name("CentOS Update for libuser CESA-2011:0170 centos4 i386");

  script_description(desc);
  script_summary("Check for the Version of libuser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"libuser", rpm:"libuser~0.52.5~1.1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-devel", rpm:"libuser-devel~0.52.5~1.1.el4_8.1", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
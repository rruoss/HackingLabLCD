###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ipa-admintools CESA-2013:0188 centos6 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Red Hat Identity Management is a centralized authentication, identity
  management and authorization solution for both traditional and cloud-based
  enterprise environments.

  A weakness was found in the way IPA clients communicated with IPA servers
  when initially attempting to join IPA domains. As there was no secure way
  to provide the IPA server's Certificate Authority (CA) certificate to the
  client during a join, the IPA client enrollment process was susceptible to
  man-in-the-middle attacks. This flaw could allow an attacker to obtain
  access to the IPA server using the credentials provided by an IPA client,
  including administrative access to the entire domain if the join was
  performed using an administrator's credentials. (CVE-2012-5484)
  
  Note: This weakness was only exposed during the initial client join to the
  realm, because the IPA client did not yet have the CA certificate of the
  server. Once an IPA client has joined the realm and has obtained the CA
  certificate of the IPA server, all further communication is secure. If a
  client were using the OTP (one-time password) method to join to the realm,
  an attacker could only obtain unprivileged access to the server (enough to
  only join the realm).
  
  Red Hat would like to thank Petr Menk for reporting this issue.
  
  This update must be installed on both the IPA client and IPA server. When
  this update has been applied to the client but not the server,
  ipa-client-install, in unattended mode, will fail if you do not have the
  correct CA certificate locally, noting that you must use the &quot;--force&quot;
  option to insecurely obtain the certificate. In interactive mode, the
  certificate will try to be obtained securely from LDAP. If this fails, you
  will be prompted to insecurely download the certificate via HTTP. In the
  same situation when using OTP, LDAP will not be queried and you will be
  prompted to insecurely download the certificate via HTTP.
  
  Users of ipa are advised to upgrade to these updated packages, which
  correct this issue. After installing the update, changes in LDAP are
  handled by ipa-ldap-updater automatically and are effective immediately.";


tag_affected = "ipa-admintools on CentOS 6";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-January/019213.html");
  script_id(881580);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-24 09:27:44 +0530 (Thu, 24 Jan 2013)");
  script_cve_id("CVE-2012-5484");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2013:0188");
  script_name("CentOS Update for ipa-admintools CESA-2013:0188 centos6 ");

  script_description(desc);
  script_summary("Check for the Version of ipa-admintools");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"ipa-admintools", rpm:"ipa-admintools~2.2.0~17.el6_3.1", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-client", rpm:"ipa-client~2.2.0~17.el6_3.1", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-python", rpm:"ipa-python~2.2.0~17.el6_3.1", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server", rpm:"ipa-server~2.2.0~17.el6_3.1", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa-server-selinux", rpm:"ipa-server-selinux~2.2.0~17.el6_3.1", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ipa", rpm:"ipa~2.2.0~17.el6_3.1", rls:"CentOS6")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
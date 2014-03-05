###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for pam_krb5 RHSA-2010:0258-04
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
tag_insight = "The pam_krb5 module allows Pluggable Authentication Modules (PAM) aware
  applications to use Kerberos to verify user identities by obtaining user
  credentials at log in time.

  A flaw was found in pam_krb5. In some non-default configurations
  (specifically, those where pam_krb5 would be the first module to prompt for
  a password), the text of the password prompt varied based on whether or not
  the username provided was a username known to the system. A remote attacker
  could use this flaw to recognize valid usernames, which would aid a
  dictionary-based password guess attack. (CVE-2009-1384)
  
  This update also fixes the following bugs:
  
  * certain applications which do not properly implement PAM conversations
  may fail to authenticate users whose passwords have expired and must be
  changed, or may succeed without forcing the user's password to be changed.
  This bug is triggered by a previously-applied fix to pam_krb5 which makes
  it comply more closely to PAM specifications. If an application misbehaves,
  enabling the &quot;chpw_prompt&quot; option for its service should restore the old
  behavior. (BZ#509092)
  
  * pam_krb5 does not allow the user to change an expired password in cases
  where the Key Distribution Center (KDC) is configured to refuse attempts to
  obtain forwardable password-changing credentials. This update fixes this
  issue. (BZ#489015)
  
  * failure to verify TGT because of wrong keytab handling. (BZ#450776)
  
  Users of pam_krb5 are advised to upgrade to these updated packages, which
  resolve these issues.";

tag_affected = "pam_krb5 on Red Hat Enterprise Linux (v. 5 server)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-March/msg00034.html");
  script_id(870247);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:56:44 +0200 (Tue, 06 Apr 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2010:0258-04");
  script_cve_id("CVE-2009-1384");
  script_name("RedHat Update for pam_krb5 RHSA-2010:0258-04");

  script_description(desc);
  script_summary("Check for the Version of pam_krb5");
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

  if ((res = isrpmvuln(pkg:"pam_krb5", rpm:"pam_krb5~2.2.14~15", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pam_krb5-debuginfo", rpm:"pam_krb5-debuginfo~2.2.14~15", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

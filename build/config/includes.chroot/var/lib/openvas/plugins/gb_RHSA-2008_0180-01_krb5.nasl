###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for krb5 RHSA-2008:0180-01
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
tag_insight = "Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other through use of symmetric encryption
  and a trusted third party, the KDC.

  A flaw was found in the way the MIT Kerberos Authentication Service and Key
  Distribution Center server (krb5kdc) handled Kerberos v4 protocol packets.
  An unauthenticated remote attacker could use this flaw to crash the
  krb5kdc daemon, disclose portions of its memory, or possibly execute
  arbitrary code using malformed or truncated Kerberos v4 protocol
  requests. (CVE-2008-0062, CVE-2008-0063)
  
  This issue only affected krb5kdc with Kerberos v4 protocol compatibility
  enabled, which is the default setting on Red Hat Enterprise Linux 4.
  Kerberos v4 protocol support can be disabled by adding &quot;v4_mode=none&quot;
  (without the quotes) to the &quot;[kdcdefaults]&quot; section of
  /var/kerberos/krb5kdc/kdc.conf.
  
  Red Hat would like to thank MIT for reporting these issues.
  
  A double-free flaw was discovered in the GSSAPI library used by MIT
  Kerberos. This flaw could possibly cause a crash of the application using
  the GSSAPI library. (CVE-2007-5971)
  
  All krb5 users are advised to update to these erratum packages which
  contain backported fixes to correct these issues.";

tag_affected = "krb5 on Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-March/msg00010.html");
  script_id(870009);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "RHSA", value: "2008:0180-01");
  script_cve_id("CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063");
  script_name( "RedHat Update for krb5 RHSA-2008:0180-01");

  script_description(desc);
  script_summary("Check for the Version of krb5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"krb5-debuginfo", rpm:"krb5-debuginfo~1.3.4~54.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.3.4~54.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.3.4~54.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.3.4~54.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.3.4~54.el4_6.1", rls:"RHENT_4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

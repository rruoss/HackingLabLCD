###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for krb5 MDVSA-2008:070 (krb5)
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
tag_insight = "A memory management flaw was found in the GSSAPI library used by
  Kerberos that could result in an attempt to free already freed memory,
  possibly leading to a crash or allowing the execution of arbitrary code
  (CVE-2007-5971).

  A flaw was discovered in how the Kerberos krb5kdc handled Kerberos v4
  protocol packets.  An unauthenticated remote attacker could use this
  flaw to crash the krb5kdc daemon, disclose portions of its memory,
  or possibly %execute arbitrary code using malformed or truncated
  Kerberos v4 protocol requests (CVE-2008-0062, CVE-2008-0063).
  
  This issue only affects krb5kdc when it has Kerberos v4 protocol
  compatibility enabled, which is a compiled-in default in all
  Kerberos versions that Mandriva Linux ships prior to Mandriva
  Linux 2008.0.  Kerberos v4 protocol support can be disabled by
  adding v4_mode=none (without quotes) to the [kdcdefaults] section
  of /etc/kerberos/krb5kdc/kdc.conf.
  
  A flaw in the RPC library as used in Kerberos' kadmind was discovered
  by Jeff Altman of Secure Endpoints.  An unauthenticated remote attacker
  could use this vulnerability to crash kadmind or possibly execute
  arbitrary code in systems with certain resource limits configured;
  this does not affect the default resource limits used by Mandriva Linux
  (CVE-2008-0947).
  
  The updated packages have been patched to correct these issues.";

tag_affected = "krb5 on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-03/msg00019.php");
  script_id(830397);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:18:58 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "MDVSA", value: "2008:070");
  script_cve_id("CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_name( "Mandriva Update for krb5 MDVSA-2008:070 (krb5)");

  script_description(desc);
  script_summary("Check for the Version of krb5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
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

if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"ftp-client-krb5", rpm:"ftp-client-krb5~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ftp-server-krb5", rpm:"ftp-server-krb5~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"telnet-client-krb5", rpm:"telnet-client-krb5~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"telnet-server-krb5", rpm:"telnet-server-krb5~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.4.3~7.4mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for proftpd MDKSA-2007:130 (proftpd)
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
tag_insight = "The Auth API in ProFTPD, when multiple simultaneous authentication
  modules are configured, did not require that the module that checks
  authentication is the same module that retrieves authentication data,
  which could possibly be used to allow remote attackers to bypass
  authentication.

  The updated packages have been patched to prevent this issue.  As well,
  this update provides proper PAM configuration files for ProFTPD
  on Corporate Server 4 that had prevented any mod_auth_pam-based
  connections from succeeding authentication.
  
  As well, ProFTPD 1.3.0 is being provided for Corporate 3 and Corporate
  Server 4.";

tag_affected = "proftpd on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-06/msg00030.php");
  script_id(830311);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:57:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "MDKSA", value: "2007:130");
  script_cve_id("CVE-2007-2165");
  script_name( "Mandriva Update for proftpd MDKSA-2007:130 (proftpd)");

  script_description(desc);
  script_summary("Check for the Version of proftpd");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-devel", rpm:"proftpd-devel~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_autohost", rpm:"proftpd-mod_autohost~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ban", rpm:"proftpd-mod_ban~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_case", rpm:"proftpd-mod_case~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_clamav", rpm:"proftpd-mod_clamav~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ctrls_admin", rpm:"proftpd-mod_ctrls_admin~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_gss", rpm:"proftpd-mod_gss~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ifsession", rpm:"proftpd-mod_ifsession~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ldap", rpm:"proftpd-mod_ldap~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_load", rpm:"proftpd-mod_load~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab", rpm:"proftpd-mod_quotatab~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_file", rpm:"proftpd-mod_quotatab_file~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_ldap", rpm:"proftpd-mod_quotatab_ldap~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_radius", rpm:"proftpd-mod_quotatab_radius~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_sql", rpm:"proftpd-mod_quotatab_sql~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_radius", rpm:"proftpd-mod_radius~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ratio", rpm:"proftpd-mod_ratio~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_rewrite", rpm:"proftpd-mod_rewrite~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_shaper", rpm:"proftpd-mod_shaper~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_site_misc", rpm:"proftpd-mod_site_misc~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_sql", rpm:"proftpd-mod_sql~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_sql_mysql", rpm:"proftpd-mod_sql_mysql~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_sql_postgres", rpm:"proftpd-mod_sql_postgres~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_time", rpm:"proftpd-mod_time~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_tls", rpm:"proftpd-mod_tls~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_wrap", rpm:"proftpd-mod_wrap~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_wrap_file", rpm:"proftpd-mod_wrap_file~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_wrap_sql", rpm:"proftpd-mod_wrap_sql~1.3.1~0.rc2.3.2mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-anonymous", rpm:"proftpd-anonymous~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_autohost", rpm:"proftpd-mod_autohost~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_case", rpm:"proftpd-mod_case~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_clamav", rpm:"proftpd-mod_clamav~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ctrls_admin", rpm:"proftpd-mod_ctrls_admin~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_facl", rpm:"proftpd-mod_facl~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_gss", rpm:"proftpd-mod_gss~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ifsession", rpm:"proftpd-mod_ifsession~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ldap", rpm:"proftpd-mod_ldap~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_load", rpm:"proftpd-mod_load~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab", rpm:"proftpd-mod_quotatab~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_file", rpm:"proftpd-mod_quotatab_file~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_ldap", rpm:"proftpd-mod_quotatab_ldap~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_quotatab_sql", rpm:"proftpd-mod_quotatab_sql~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_radius", rpm:"proftpd-mod_radius~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_ratio", rpm:"proftpd-mod_ratio~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_rewrite", rpm:"proftpd-mod_rewrite~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_shaper", rpm:"proftpd-mod_shaper~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_site_misc", rpm:"proftpd-mod_site_misc~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_sql", rpm:"proftpd-mod_sql~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_sql_mysql", rpm:"proftpd-mod_sql_mysql~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_sql_postgres", rpm:"proftpd-mod_sql_postgres~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_time", rpm:"proftpd-mod_time~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_tls", rpm:"proftpd-mod_tls~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_wrap", rpm:"proftpd-mod_wrap~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_wrap_file", rpm:"proftpd-mod_wrap_file~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"proftpd-mod_wrap_sql", rpm:"proftpd-mod_wrap_sql~1.3.0~4.5mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

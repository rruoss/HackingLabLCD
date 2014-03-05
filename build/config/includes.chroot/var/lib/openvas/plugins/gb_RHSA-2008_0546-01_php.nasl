###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for php RHSA-2008:0546-01
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
tag_insight = "PHP is an HTML-embedded scripting language commonly used with the Apache
  HTTP Web server.

  It was discovered that the PHP escapeshellcmd() function did not properly
  escape multi-byte characters which are not valid in the locale used by the
  script. This could allow an attacker to bypass quoting restrictions imposed
  by escapeshellcmd() and execute arbitrary commands if the PHP script was
  using certain locales. Scripts using the default UTF-8 locale are not
  affected by this issue. (CVE-2008-2051)
  
  The PHP functions htmlentities() and htmlspecialchars() did not properly
  recognize partial multi-byte sequences. Certain sequences of bytes could be
  passed through these functions without being correctly HTML-escaped.
  Depending on the browser being used, an attacker could use this flaw to
  conduct cross-site scripting attacks. (CVE-2007-5898)
  
  A PHP script which used the transparent session ID configuration option, or
  which used the output_add_rewrite_var() function, could leak session
  identifiers to external web sites. If a page included an HTML form with an
  ACTION attribute referencing a non-local URL, the user's session ID would
  be included in the form data passed to that URL. (CVE-2007-5899)
  
  It was discovered that PHP did not properly seed its pseudo-random number
  generator used by functions such as rand() and mt_rand(), possibly allowing
  an attacker to easily predict the generated pseudo-random values.
  (CVE-2008-2107, CVE-2008-2108)
  
  Integer overflow and memory requirements miscalculation issues were
  discovered in the Perl-Compatible Regular Expression (PCRE) library used by
  PHP to process regular expressions. These issues could cause a crash, or
  possibly execute an arbitrary code with the privileges of the PHP script
  that processes regular expressions from untrusted sources. Note: PHP
  packages shipped with Red Hat Enterprise Linux 2.1 did not use the
  system-level PCRE library. By default they used an embedded copy of the
  library included with the PHP package. (CVE-2006-7228, CVE-2007-1660)
  
  Users of PHP should upgrade to these updated packages, which contain
  backported patches to correct these issues.";

tag_affected = "php on Red Hat Enterprise Linux AS (Advanced Server) version 2.1,
  Red Hat Enterprise Linux ES version 2.1,
  Red Hat Enterprise Linux WS version 2.1";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2008-July/msg00018.html");
  script_id(870113);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-06 07:30:35 +0100 (Fri, 06 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "RHSA", value: "2008:0546-01");
  script_cve_id("CVE-2008-2051", "CVE-2007-5898", "CVE-2007-5899", "CVE-2006-7228", "CVE-2007-1660", "CVE-2008-2107", "CVE-2008-2108");
  script_name( "RedHat Update for php RHSA-2008:0546-01");

  script_description(desc);
  script_summary("Check for the Version of php");
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

if(release == "RHENT_2.1")
{

  if ((res = isrpmvuln(pkg:"php", rpm:"php~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-devel", rpm:"php-devel~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-imap", rpm:"php-imap~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-ldap", rpm:"php-ldap~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-manual", rpm:"php-manual~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-mysql", rpm:"php-mysql~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-odbc", rpm:"php-odbc~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"php-pgsql", rpm:"php-pgsql~4.1.2~2.20", rls:"RHENT_2.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

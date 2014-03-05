###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for openssl MDVSA-2008:107 (openssl)
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
tag_insight = "Testing using the Codenomicon TLS test suite discovered a flaw in
  the handling of server name extension data in OpenSSL 0.9.8f and
  OpenSSL 0.9.8g.  If OpenSSL has been compiled using the non-default
  TLS server name extensions, a remote attacker could send a carefully
  crafted packet to a server application using OpenSSL and cause a
  crash. (CVE-2008-0891)

  Testing using the Codenomicon TLS test suite discovered a flaw if
  the 'Server Key exchange message' is omitted from a TLS handshake
  in OpenSSL 0.9.8f and OpenSSL 0.9.8g.  If a client connects to a
  malicious server with particular cipher suites, the server could
  cause the client to crash. (CVE-2008-1672)
  
  The updated packages have been patched to fix these flaws.
  
  Note that any applications using this library must be restarted for
  the update to take effect.";

tag_affected = "openssl on Mandriva Linux 2008.1,
  Mandriva Linux 2008.1/X86_64";
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
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2008-05/msg00032.php");
  script_id(830697);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-09 14:26:37 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVSA", value: "2008:107");
  script_cve_id("CVE-2008-0891", "CVE-2008-1672");
  script_name( "Mandriva Update for openssl MDVSA-2008:107 (openssl)");

  script_description(desc);
  script_summary("Check for the Version of openssl");
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

if(release == "MNDK_2008.1")
{

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8", rpm:"libopenssl0.9.8~0.9.8g~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-devel", rpm:"libopenssl0.9.8-devel~0.9.8g~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0.9.8-static-devel", rpm:"libopenssl0.9.8-static-devel~0.9.8g~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8g~4.1mdv2008.0", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8", rpm:"lib64openssl0.9.8~0.9.8g~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-devel", rpm:"lib64openssl0.9.8-devel~0.9.8g~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64openssl0.9.8-static-devel", rpm:"lib64openssl0.9.8-static-devel~0.9.8g~4.1mdv2008.1", rls:"MNDK_2008.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openssl vulnerability USN-990-1
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
tag_insight = "Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
  protocols. If an attacker could perform a man in the middle attack at the
  start of a TLS connection, the attacker could inject arbitrary content at
  the beginning of the user's session. This update adds backported support
  for the new RFC5746 renegotiation extension and will use it when both the
  client and the server support it.

  ATTENTION: After applying this update, a patched server will allow both
  patched and unpatched clients to connect, but unpatched clients will not be
  able to renegotiate. For more information, please refer to the following:
  http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
  http://www.openssl.org/docs/ssl/SSL_CTX_set_options.html";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-990-1";
tag_affected = "openssl vulnerability on Ubuntu 6.06 LTS ,
  Ubuntu 8.04 LTS ,
  Ubuntu 9.04 ,
  Ubuntu 9.10 ,
  Ubuntu 10.04 LTS";
tag_solution = "Please Install the Updated Packages.";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution + "


  ";

if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2010-September/001164.html");
  script_id(840505);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-27 08:14:44 +0200 (Mon, 27 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "990-1");
  script_cve_id("CVE-2009-3555");
  script_name("Ubuntu Update for openssl vulnerability USN-990-1");

  script_description(desc);
  script_summary("Check for the Version of openssl vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-16ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-16ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-16ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-16ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-doc", ver:"0.9.8g-16ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8g-16ubuntu3.2", rls:"UBUNTU9.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8a-7ubuntu0.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8a-7ubuntu0.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8a-7ubuntu0.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8a-7ubuntu0.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8a-7ubuntu0.12", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8k-7ubuntu8.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8k-7ubuntu8.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8k-7ubuntu8.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8k-7ubuntu8.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-doc", ver:"0.9.8k-7ubuntu8.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8k-7ubuntu8.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8-udeb", ver:"0.9.8k-7ubuntu8.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU9.04")
{

  if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-15ubuntu3.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-15ubuntu3.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-15ubuntu3.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-15ubuntu3.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-doc", ver:"0.9.8g-15ubuntu3.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8g-15ubuntu3.5", rls:"UBUNTU9.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-4ubuntu3.10", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-4ubuntu3.10", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-4ubuntu3.10", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-4ubuntu3.10", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"openssl-doc", ver:"0.9.8g-4ubuntu3.10", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8g-4ubuntu3.10", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

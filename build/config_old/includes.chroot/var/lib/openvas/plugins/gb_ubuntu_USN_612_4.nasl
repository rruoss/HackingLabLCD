###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for ssl-cert vulnerability USN-612-4
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
tag_insight = "USN-612-1 fixed vulnerabilities in openssl.  This update provides the
  corresponding updates for ssl-cert -- potentially compromised snake-oil
  SSL certificates will be regenerated.

  Original advisory details:
  
  A weakness has been discovered in the random number generator used
  by OpenSSL on Debian and Ubuntu systems.  As a result of this
  weakness, certain encryption keys are much more common than they
  should be, such that an attacker could guess the key through a
  brute-force attack given minimal knowledge of the system.  This
  particularly affects the use of encryption keys in OpenSSH, OpenVPN
  and SSL certificates.
  
  This vulnerability only affects operating systems which (like
  Ubuntu) are based on Debian.  However, other systems can be
  indirectly affected if weak keys are imported into them.
  
  We consider this an extremely serious vulnerability, and urge all
  users to act immediately to secure their systems. (CVE-2008-0166)
  
  == Who is affected ==
  
  Systems which are running any of the following releases:
  
  * Ubuntu 7.04 (Feisty)
  * Ubuntu 7.10 (Gutsy)
  * Ubuntu 8.04 LTS (Hardy)
  * Ubuntu &quot;Intrepid Ibex&quot; (development): libssl &lt;= 0.9.8g-8
  * Debian 4.0 (etch) (see corresponding Debian security advisory)
  
  and have openssh-server installed or have been used to create an
  OpenSSH key or X.509 (SSL) certificate.
  
  All OpenSSH and X.509 keys generated on such systems must be
  considered untrustworthy, regardless of the system on which they
  are used, even after the update has been applied.
  
  This includes the automatically generated host keys used by OpenSSH,
  which are the basis for its server spoofing and man-in-the-middle
  protection.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-612-4";
tag_affected = "ssl-cert vulnerability on Ubuntu 7.04 ,
  Ubuntu 7.10 ,
  Ubuntu 8.04 LTS";
tag_solution = "Please Install the Updated Packages.";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-May/000708.html");
  script_id(840338);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "612-4");
  script_cve_id("CVE-2008-0166");
  script_name( "Ubuntu Update for ssl-cert vulnerability USN-612-4");

  script_description(desc);
  script_summary("Check for the Version of ssl-cert vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "UBUNTU7.04")
{

  if ((res = isdpkgvuln(pkg:"ssl-cert", ver:"1.0.13-0ubuntu0.7.04.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ssl-cert", ver:"1.0.14-0ubuntu2.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"ssl-cert", ver:"1.0.14-0ubuntu0.7.10.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

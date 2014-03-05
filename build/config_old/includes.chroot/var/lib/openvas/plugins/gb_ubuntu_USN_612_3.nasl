###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for openvpn vulnerability USN-612-3
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
tag_insight = "Once the update is applied, weak shared encryption keys and
  SSL/TLS certificates will be rejected where possible (though
  they cannot be detected in all cases). If you are using such
  keys or certificates, OpenVPN will not start and the keys or
  certificates will need to be regenerated.

  The safest course of action is to regenerate all OpenVPN
  certificates and key files, except where it can be established
  to a high degree of certainty that the certificate or shared key
  was generated on an unaffected system.
  
  Once the update is applied, you can check for weak OpenVPN shared
  secret keys with the openvpn-vulnkey command.
  
  $ openvpn-vulnkey /path/to/key
  
  OpenVPN shared keys can be regenerated using the openvpn command.
  
  $ openvpn --genkey --secret &lt;file&gt;
  
  Additionally, you can check for weak SSL/TLS certificates by
  installing openssl-blacklist via your package manager, and using
  the openssl-vulkey command.
  
  $ openssl-vulnkey /path/to/key
  
  Please note that openssl-vulnkey only checks RSA private keys
  with 1024 and 2048 bit lengths. If in doubt, destroy the
  certificate and/or key and generate a new one. Please consult the
  OpenVPN documention when recreating SSL/TLS certificates.
  
  Additionally, if certificates have been generated for use on other
  systems, they must be found and replaced as well.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-612-3";
tag_affected = "openvpn vulnerability on Ubuntu 7.04 ,
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2008-May/000707.html");
  script_id(840286);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:59:50 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "612-3");
  script_cve_id("CVE-2008-0166");
  script_name( "Ubuntu Update for openvpn vulnerability USN-612-3");

  script_description(desc);
  script_summary("Check for the Version of openvpn vulnerability");
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

  if ((res = isdpkgvuln(pkg:"openvpn", ver:"2.0.9-5ubuntu0.1", rls:"UBUNTU7.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"openvpn", ver:"2.1~rc7-1ubuntu3.1", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU7.10")
{

  if ((res = isdpkgvuln(pkg:"openvpn", ver:"2.0.9-8ubuntu0.1", rls:"UBUNTU7.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

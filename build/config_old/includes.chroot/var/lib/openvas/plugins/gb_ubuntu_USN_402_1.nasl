###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for avahi vulnerability USN-402-1
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
tag_insight = "A flaw was discovered in Avahi's handling of compressed DNS packets.  If
  a specially crafted reply were received over the network, the Avahi
  daemon would go into an infinite loop, causing a denial of service.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-402-1";
tag_affected = "avahi vulnerability on Ubuntu 5.10 ,
  Ubuntu 6.06 LTS ,
  Ubuntu 6.10";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-January/000461.html");
  script_id(840023);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "USN", value: "402-1");
  script_cve_id("CVE-2006-6870");
  script_name( "Ubuntu Update for avahi vulnerability USN-402-1");

  script_description(desc);
  script_summary("Check for the Version of avahi vulnerability");
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

if(release == "UBUNTU6.06 LTS")
{

  if ((res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-utils", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-client3", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common-data", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common3", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-howl-dev", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-howl0", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd-dev", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd1", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-core4", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-glib1", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt3-1", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt3-dev", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-discover", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-cil", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"monodoc-avahi-manual", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python2.4-avahi", ver:"0.6.10-0ubuntu3.4", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-utils", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-client3", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common-data", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common3", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-howl-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-howl0", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-compat-libdnssd1", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-core4", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-glib1", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt3-1", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt3-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt4-1", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt4-dev", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-discover", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python-avahi", ver:"0.6.13-2ubuntu2.4", rls:"UBUNTU6.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU5.10")
{

  if ((res = isdpkgvuln(pkg:"avahi-daemon", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-dnsconfd", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-client-dev", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-client1", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common-dev", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-common0", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-core-dev", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-core1", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-glib-dev", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-glib0", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt3-0", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt3-dev", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt4-0", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-qt4-dev", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"avahi-utils", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavahi-cil", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python2.4-avahi", ver:"0.5.2-1ubuntu1.4", rls:"UBUNTU5.10")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

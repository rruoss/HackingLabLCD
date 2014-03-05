###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for xorg, xorg-server vulnerabilities USN-403-1
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
tag_insight = "The DBE and Render extensions in X.org were vulnerable to integer
  overflows, which could lead to memory overwrites.  An authenticated user
  could make a specially crafted request and execute arbitrary code with
  root privileges.";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-403-1";
tag_affected = "xorg, xorg-server vulnerabilities on Ubuntu 5.10 ,
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2007-January/000462.html");
  script_id(840159);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-23 10:55:18 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "403-1");
  script_cve_id("CVE-2006-6101", "CVE-2006-6102", "CVE-2006-6103");
  script_name( "Ubuntu Update for xorg, xorg-server vulnerabilities USN-403-1");

  script_description(desc);
  script_summary("Check for the Version of xorg, xorg-server vulnerabilities");
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

  if ((res = isdpkgvuln(pkg:"xdmx-tools", ver:"1.0.2-0ubuntu10.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xdmx", ver:"1.0.2-0ubuntu10.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xnest", ver:"1.0.2-0ubuntu10.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"1.0.2-0ubuntu10.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"1.0.2-0ubuntu10.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xvfb", ver:"1.0.2-0ubuntu10.5", rls:"UBUNTU6.06 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU6.10")
{

  if ((res = isdpkgvuln(pkg:"xdmx-tools", ver:"1.1.1-0ubuntu12.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xdmx", ver:"1.1.1-0ubuntu12.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xnest", ver:"1.1.1-0ubuntu12.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xephyr", ver:"1.1.1-0ubuntu12.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"1.1.1-0ubuntu12.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-dev", ver:"1.1.1-0ubuntu12.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xvfb", ver:"1.1.1-0ubuntu12.1", rls:"UBUNTU6.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU5.10")
{

  if ((res = isdpkgvuln(pkg:"x-window-system-core", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"x-window-system-dev", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xdmx", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xlibs-static-dev", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xlibs-static-pic", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xnest", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-common", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-dbg", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-apm", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-ark", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-ati", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-chips", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-cirrus", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-cyrix", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-dummy", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-fbdev", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-glide", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-glint", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-i128", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-i740", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-i810", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-imstt", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-mga", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-neomagic", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-newport", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-nsc", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-nv", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-rendition", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-s3", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-s3virge", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-savage", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-siliconmotion", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-sis", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-tdfx", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-tga", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-trident", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-tseng", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-v4l", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-vesa", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-vga", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-via", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-driver-vmware", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-acecad", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-aiptek", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-calcomp", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-citron", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-digitaledge", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-dmc", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-dynapro", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-elographics", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-fpit", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-hyperpen", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-kbd", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-magellan", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-microtouch", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-mouse", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-mutouch", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-palmax", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-penmount", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-spaceorb", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-summa", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-tek4957", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-void", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg-input-wacom", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xserver-xorg", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xvfb", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xbase-clients", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xlibs-data", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xlibs-dev", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xlibs", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xorg-common", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"xutils", ver:"6.8.2-77.2", rls:"UBUNTU5.10")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

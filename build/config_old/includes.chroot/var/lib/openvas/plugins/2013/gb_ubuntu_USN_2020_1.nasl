###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-lts-raring USN-2020-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(841618);
  script_version("$Revision: 74 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 13:29:03 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-18 15:45:27 +0530 (Mon, 18 Nov 2013)");
  script_cve_id("CVE-2013-0343", "CVE-2013-2147", "CVE-2013-2889", "CVE-2013-2893",
                "CVE-2013-2894", "CVE-2013-2895", "CVE-2013-2897", "CVE-2013-4343");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ubuntu Update for linux-lts-raring USN-2020-1");

  tag_insight = "An information leak was discovered in the handling of ICMPv6
Router Advertisement (RA) messages in the Linux kernel's IPv6 network stack. A
remote attacker could exploit this flaw to cause a denial of service
(excessive retries and address-generation outage), and consequently obtain
sensitive information. (CVE-2013-0343)

Dan Carpenter discovered an information leak in the HP Smart Aray and
Compaq SMART2 disk-array driver in the Linux kernel. A local user could
exploit this flaw to obtain sensitive information from kernel memory.
(CVE-2013-2147)

Kees Cook discovered flaw in the Human Interface Device (HID) subsystem
when CONFIG_HID_ZEROPLUS is enabled. A physically proximate attacker could
leverage this flaw to cause a denial of service via a specially crafted
device. (CVE-2013-2889)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when any of CONFIG_LOGITECH_FF,
CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF are enabled. A physcially
proximate attacker can leverage this flaw to cause a denial of service vias
a specially crafted device. (CVE-2013-2893)

Kees Cook discovered a flaw in the Human Interface Device (HID) subsystem
of the Linux kernel when CONFIG_HID_LENOVO_TPKBD is enabled. A physically
proximate attacker could exploit this flaw to cause a denial of service via
a specially crafted device. (CVE-2013-2894)

Kees Cook discovered another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_LOGITECH_DJ is enabled. A
physically proximate attacker could cause a denial of service (OOPS) or
obtain sensitive information from kernel memory via a specially crafted
device. (CVE-2013-2895)

Kees Cook discovered yet another flaw in the Human Interface Device (HID)
subsystem of the Linux kernel when CONFIG_HID_MULTITOUCH is enabled. A
physically proximate attacker could leverage this flaw to cause a denial of
service (OOPS) via a specially crafted device. (CVE-2013-2897)

Wannes Rombouts reported a vulnerability in the networking tuntap interface
of the Linux kernel. A local user with the CAP_NET_ADMIN capability could
leverage this flaw to gain full admin privileges. (CVE-2013-4343)";

  tag_affected = "linux-lts-raring on Ubuntu 12.04 LTS";

  tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  script_description(desc);
  script_xref(name: "USN", value: "2020-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-November/002312.html");
  script_summary("Check for the Version of linux-lts-raring");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success", "HostDetails/OS/cpe:/o:canonical:ubuntu_linux", "ssh/login/release");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU12.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-3.8.0-33-generic", ver:"3.8.0-33.48~precise1", rls:"UBUNTU12.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

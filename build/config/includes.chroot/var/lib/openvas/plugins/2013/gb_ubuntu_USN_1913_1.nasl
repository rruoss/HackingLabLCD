###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for linux-ec2 USN-1913-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_id(841516);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-08 11:43:33 +0530 (Thu, 08 Aug 2013)");
  script_cve_id("CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237",
                "CVE-2013-2851");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Ubuntu Update for linux-ec2 USN-1913-1");

  tag_insight = "Jonathan Salwan discovered an information leak in the Linux kernel's cdrom
driver. A local user can exploit this leak to obtain sensitive information
from kernel memory if the CD-ROM drive is malfunctioning. (CVE-2013-2164)

A flaw was discovered in the Linux kernel when an IPv6 socket is used to
connect to an IPv4 destination. An unprivileged local user could exploit
this flaw to cause a denial of service (system crash). (CVE-2013-2232)

An information leak was discovered in the IPSec key_socket implementation
in the Linux kernel. An local user could exploit this flaw to examine
potentially sensitive information in kernel memory. (CVE-2013-2234)

An information leak was discovered in the Linux kernel's IPSec key_socket
when using the notify_policy interface. A local user could exploit this
flaw to examine potentially sensitive information in kernel memory.
(CVE-2013-2237)

Kees Cook discovered a format string vulnerability in the Linux kernel's
disk block layer. A local user with administrator privileges could exploit
this flaw to gain kernel privileges. (CVE-2013-2851)";

  tag_affected = "linux-ec2 on Ubuntu 10.04 LTS";

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
  script_xref(name: "USN", value: "1913-1");
  script_xref(name: "URL" , value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2013-July/002200.html");
  script_summary("Check for the Version of linux-ec2");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"linux-image-2.6.32-355-ec2", ver:"2.6.32-355.68", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

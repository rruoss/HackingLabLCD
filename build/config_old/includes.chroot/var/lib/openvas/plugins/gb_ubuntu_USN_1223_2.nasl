###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for puppet USN-1223-2
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "USN-1223-1 fixed vulnerabilities in Puppet. A regression was found on
  Ubuntu 10.04 LTS that caused permission denied errors when managing SSH
  authorized_keys files with Puppet. This update fixes the problem.

  We apologize for the inconvenience.
  
  Original advisory details:
  
  It was discovered that Puppet unsafely opened files when the k5login type
  is used to manage files. A local attacker could exploit this to overwrite
  arbitrary files which could be used to escalate privileges. (CVE-2011-3869)
  
  Ricky Zhou discovered that Puppet did not drop privileges when creating
  SSH authorized_keys files. A local attacker could exploit this to overwrite
  arbitrary files as root. (CVE-2011-3870)
  
  It was discovered that Puppet used a predictable filename when using the
  --edit resource. A local attacker could exploit this to edit arbitrary
  files or run arbitrary code as the user invoking the program, typically
  root. (CVE-2011-3871)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1223-2";
tag_affected = "puppet on Ubuntu 10.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-October/001441.html");
  script_id(840766);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-10 16:05:48 +0200 (Mon, 10 Oct 2011)");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1223-2");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");
  script_cve_id("CVE-2011-3869", "CVE-2011-3870", "CVE-2011-3871");
  script_name("Ubuntu Update for puppet USN-1223-2");

  script_description(desc);
  script_summary("Check for the Version of puppet");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"puppet-common", ver:"0.25.4-2ubuntu6.4", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

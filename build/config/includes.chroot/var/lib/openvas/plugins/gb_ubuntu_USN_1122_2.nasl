###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for thunderbird USN-1122-2
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
tag_insight = "USN-1122-1 fixed vulnerabilities in Thunderbird for Lucid and Maverick.
  This update provides the corresponding fixes for Natty.

  Original advisory details:
  
  It was discovered that there was a vulnerability in the memory handling of
  certain types of content. An attacker could exploit this to possibly run
  arbitrary code as the user running Thunderbird. (CVE-2011-0081)
  
  It was discovered that Thunderbird incorrectly handled certain JavaScript
  requests. If JavaScript were enabled, an attacker could exploit this to
  possibly run arbitrary code as the user running Thunderbird.
  (CVE-2011-0069)
  
  Ian Beer discovered a vulnerability in the memory handling of a certain
  types of documents. An attacker could exploit this to possibly run
  arbitrary code as the user running Thunderbird. (CVE-2011-0070)
  
  Bob Clary, Henri Sivonen, Marco Bonardo, Mats Palmgren and Jesse Ruderman
  discovered several memory vulnerabilities. An attacker could exploit these
  to possibly run arbitrary code as the user running Thunderbird.
  (CVE-2011-0080)
  
  Aki Helin discovered multiple vulnerabilities in the HTML rendering code.
  An attacker could exploit these to possibly run arbitrary code as the user
  running Thunderbird. (CVE-2011-0074, CVE-2011-0075)
  
  Ian Beer discovered multiple overflow vulnerabilities. An attacker could
  exploit these to possibly run arbitrary code as the user running
  Thunderbird. (CVE-2011-0077, CVE-2011-0078)
  
  Martin Barbella discovered a memory vulnerability in the handling of
  certain DOM elements. An attacker could exploit this to possibly run
  arbitrary code as the user running Thunderbird. (CVE-2011-0072)
  
  It was discovered that there were use-after-free vulnerabilities in
  Thunderbird's mChannel and mObserverList objects. An attacker could exploit
  these to possibly run arbitrary code as the user running Thunderbird.
  (CVE-2011-0065, CVE-2011-0066)
  
  It was discovered that there was a vulnerability in the handling of the
  nsTreeSelection element. An attacker sending a specially crafted E-Mail
  could exploit this to possibly run arbitrary code as the user running
  Thunderbird. (CVE-2011-0073)
  
  Paul Stone discovered a vulnerability in the handling of Java applets. If
  plugins were enabled, an attacker could use this to mimic interaction with
  form autocomplete controls and steal entries from the form history.
  (CVE-2011-0067)
  
  Soroush Dalili discovered a vulnerability in the resource: protocol. This
  could potentially allow an attacker to load arbitrary files that were
  accessible to the user running Thunderbird. (CV ... 

  Description truncated, for more information please check the Reference URL";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1122-2";
tag_affected = "thunderbird on Ubuntu 11.04";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2011-May/001326.html");
  script_id(840650);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-10 14:04:15 +0200 (Tue, 10 May 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "USN", value: "1122-2");
  script_cve_id("CVE-2011-0081", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0080", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0072", "CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0073", "CVE-2011-0067", "CVE-2011-0071", "CVE-2011-1202");
  script_name("Ubuntu Update for thunderbird USN-1122-2");

  script_description(desc);
  script_summary("Check for the Version of thunderbird");
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

if(release == "UBUNTU11.04")
{

  if ((res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.10+build1+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

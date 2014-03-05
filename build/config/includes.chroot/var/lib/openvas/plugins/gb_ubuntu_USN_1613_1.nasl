###############################################################################
# OpenVAS Vulnerability Test
#
# Ubuntu Update for python2.5 USN-1613-1
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "It was discovered that Python would prepend an empty string to sys.path
  under certain circumstances. A local attacker with write access to the
  current working directory could exploit this to execute arbitrary code.
  (CVE-2008-5983)

  It was discovered that the audioop module did not correctly perform input
  validation. If a user or automatated system were tricked into opening a
  crafted audio file, an attacker could cause a denial of service via
  application crash. (CVE-2010-1634, CVE-2010-2089)
  
  Giampaolo Rodola discovered several race conditions in the smtpd module.
  A remote attacker could exploit this to cause a denial of service via
  daemon outage. (CVE-2010-3493)
  
  It was discovered that the CGIHTTPServer module did not properly perform
  input validation on certain HTTP GET requests. A remote attacker could
  potentially obtain access to CGI script source files. (CVE-2011-1015)
  
  Niels Heinen discovered that the urllib and urllib2 modules would process
  Location headers that specify a redirection to file: URLs. A remote
  attacker could exploit this to obtain sensitive information or cause a
  denial of service. (CVE-2011-1521)
  
  It was discovered that SimpleHTTPServer did not use a charset parameter in
  the Content-Type HTTP header. An attacker could potentially exploit this
  to conduct cross-site scripting (XSS) attacks against Internet Explorer 7
  users. (CVE-2011-4940)
  
  It was discovered that Python distutils contained a race condition when
  creating the ~/.pypirc file. A local attacker could exploit this to obtain
  sensitive information. (CVE-2011-4944)
  
  It was discovered that SimpleXMLRPCServer did not properly validate its
  input when handling HTTP POST requests. A remote attacker could exploit
  this to cause a denial of service via excessive CPU utilization.
  (CVE-2012-0845)
  
  It was discovered that the Expat module in Python 2.5 computed hash values
  without restricting the ability to trigger hash collisions predictably. If
  a user or application using pyexpat were tricked into opening a crafted XML
  file, an attacker could cause a denial of service by consuming excessive
  CPU resources. (CVE-2012-0876)
  
  Tim Boddy discovered that the Expat module in Python 2.5 did not properly
  handle memory reallocation when processing XML files. If a user or
  application using pyexpat were tricked into opening a crafted XML file, an
  attacker could cause a denial of service by consuming excessive memory
  resources. (CVE-2012-1148)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1613-1";
tag_affected = "python2.5 on Ubuntu 8.04 LTS";
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
  script_xref(name : "URL" , value : "https://lists.ubuntu.com/archives/ubuntu-security-announce/2012-October/001872.html");
  script_id(841195);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-19 09:53:57 +0530 (Fri, 19 Oct 2012)");
  script_cve_id("CVE-2008-5983", "CVE-2010-1634", "CVE-2010-2089", "CVE-2010-3493",
                "CVE-2011-1015", "CVE-2011-1521", "CVE-2011-4940", "CVE-2011-4944",
                "CVE-2012-0845", "CVE-2012-0876", "CVE-2012-1148");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "USN", value: "1613-1");
  script_name("Ubuntu Update for python2.5 USN-1613-1");

  script_description(desc);
  script_summary("Check for the Version of python2.5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"python2.5", ver:"2.5.2-2ubuntu6.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"python2.5-minimal", ver:"2.5.2-2ubuntu6.2", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

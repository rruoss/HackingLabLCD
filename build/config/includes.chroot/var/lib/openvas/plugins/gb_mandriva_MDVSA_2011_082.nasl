###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for python-feedparser MDVSA-2011:082 (python-feedparser)
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
tag_insight = "Multiple vulnerabilities has been found and corrected in
  python-feedparser:

  Cross-site scripting (XSS) vulnerability in feedparser.py in Universal
  Feed Parser (aka feedparser or python-feedparser) before 5.0 allows
  remote attackers to inject arbitrary web script or HTML via vectors
  involving nested CDATA stanzas (CVE-2009-5065).
  
  feedparser.py in Universal Feed Parser (aka feedparser or
  python-feedparser) before 5.0.1 allows remote attackers to cause
  a denial of service (application crash) via a malformed DOCTYPE
  declaration (CVE-2011-1156).
  
  Cross-site scripting (XSS) vulnerability in feedparser.py in Universal
  Feed Parser (aka feedparser or python-feedparser) 5.x before 5.0.1
  allows remote attackers to inject arbitrary web script or HTML via
  malformed XML comments (CVE-2011-1157).
  
  Cross-site scripting (XSS) vulnerability in feedparser.py in Universal
  Feed Parser (aka feedparser or python-feedparser) 5.x before 5.0.1
  allows remote attackers to inject arbitrary web script or HTML
  via an unexpected URI scheme, as demonstrated by a javascript: URI
  (CVE-2011-1158).
  
  The updated packages have been patched to correct these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "python-feedparser on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-05/msg00002.php");
  script_id(831385);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-06 16:22:00 +0200 (Fri, 06 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "MDVSA", value: "2011:082");
  script_cve_id("CVE-2009-5065", "CVE-2011-1156", "CVE-2011-1157", "CVE-2011-1158");
  script_name("Mandriva Update for python-feedparser MDVSA-2011:082 (python-feedparser)");

  script_description(desc);
  script_summary("Check for the Version of python-feedparser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"python-feedparser", rpm:"python-feedparser~4.1~8.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"python-feedparser", rpm:"python-feedparser~4.1~7.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
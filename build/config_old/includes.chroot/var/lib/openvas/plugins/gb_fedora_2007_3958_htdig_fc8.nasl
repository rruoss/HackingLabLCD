###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for htdig FEDORA-2007-3958
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
tag_insight = "The ht://Dig system is a complete world wide web indexing and searching
  system for a small domain or intranet. This system is not meant to replace
  the need for powerful internet-wide search systems like Lycos, Infoseek,
  Webcrawler and AltaVista. Instead it is meant to cover the search needs for
  a single company, campus, or even a particular sub section of a web site. As
  opposed to some WAIS-based or web-server based search engines, ht://Dig can
  span several web servers at a site. The type of these different web servers
  doesn't matter as long as they understand the HTTP 1.0 protocol.
  ht://Dig is also used by KDE to search KDE's HTML documentation.

  ht://Dig was developed at San Diego State University as a way to search the
  various web servers on the campus network.";

tag_affected = "htdig on Fedora 8";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-November/msg01025.html");
  script_id(861197);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:23:18 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2007-3958");
  script_cve_id("CVE-2007-6110");
  script_name( "Fedora Update for htdig FEDORA-2007-3958");

  script_description(desc);
  script_summary("Check for the Version of htdig");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC8")
{

  if ((res = isrpmvuln(pkg:"htdig", rpm:"htdig~3.2.0b6~13.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"htdig", rpm:"htdig~3.2.0b6~13.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"htdig-web", rpm:"htdig-web~3.2.0b6~13.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"htdig-debuginfo", rpm:"htdig-debuginfo~3.2.0b6~13.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"htdig-web", rpm:"htdig-web~3.2.0b6~13.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"htdig", rpm:"htdig~3.2.0b6~13.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"htdig-debuginfo", rpm:"htdig-debuginfo~3.2.0b6~13.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

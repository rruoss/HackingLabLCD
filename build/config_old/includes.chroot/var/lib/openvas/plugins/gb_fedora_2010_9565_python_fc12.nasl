###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for python FEDORA-2010-9565
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Python is an interpreted, interactive, object-oriented programming
  language often compared to Tcl, Perl, Scheme or Java. Python includes
  modules, classes, exceptions, very high level dynamic data types and
  dynamic typing. Python supports interfaces to many system calls and
  libraries, as well as to various windowing systems (X11, Motif, Tk,
  Mac and MFC).

  Programmers can write new built-in modules for Python in C or C++.
  Python can be used as an extension language for applications that need
  a programmable interface. This package contains most of the standard
  Python modules, as well as modules for interfacing to the Tix widget
  set for Tk and RPM.
  
  Note that documentation for Python is provided in the python-docs
  package.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "python on Fedora 12";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-July/043726.html");
  script_id(862218);
  script_version("$Revision: 14 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-06 10:05:18 +0200 (Tue, 06 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "FEDORA", value: "2010-9565");
  script_cve_id("CVE-2010-1634", "CVE-2010-2089", "CVE-2008-5983");
  script_name("Fedora Update for python FEDORA-2010-9565");

  script_description(desc);
  script_summary("Check for the Version of python");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/release");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.6.2~8.fc12", rls:"FC12")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for samba CESA-2008:0288 centos3 x86_64
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
tag_insight = "Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A heap-based buffer overflow flaw was found in the way Samba clients handle
  over-sized packets. If a client connected to a malicious Samba server, it
  was possible to execute arbitrary code as the Samba client user. It was
  also possible for a remote user to send a specially crafted print request
  to a Samba server that could result in the server executing the vulnerable
  client code, resulting in arbitrary code execution with the permissions of
  the Samba server. (CVE-2008-1105)
  
  Red Hat would like to thank Alin Rad Pop of Secunia Research for
  responsibly disclosing this issue.
  
  Users of Samba are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue.";

tag_affected = "samba on CentOS 3";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-May/014940.html");
  script_id(880215);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2008:0288");
  script_cve_id("CVE-2008-1105");
  script_name( "CentOS Update for samba CESA-2008:0288 centos3 x86_64");

  script_description(desc);
  script_summary("Check for the Version of samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.9~1.3E.15", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.9~1.3E.15", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.9~1.3E.15", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.9~1.3E.15", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for python-paramiko FEDORA-2008-0644
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
tag_affected = "python-paramiko on Fedora 8";
tag_insight = "Paramiko (a combination of the esperanto words for &quot;paranoid&quot; and &quot;friend&quot;) is
  a module for python 2.3 or greater that implements the SSH2 protocol for secure
  (encrypted and authenticated) connections to remote machines. Unlike SSL (aka
  TLS), the SSH2 protocol does not require heirarchical certificates signed by a
  powerful central authority. You may know SSH2 as the protocol that replaced
  telnet and rsh for secure access to remote shells, but the protocol also
  includes the ability to open arbitrary channels to remote services across an
  encrypted tunnel. (This is how sftp works, for example.)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2008-January/msg00529.html");
  script_id(860222);
  script_cve_id("CVE-2008-0299");
 script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-17 17:12:43 +0100 (Tue, 17 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "FEDORA", value: "2008-0644");
  script_name( "Fedora Update for python-paramiko FEDORA-2008-0644");

  script_description(desc);
  script_summary("Check for the Version of python-paramiko");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

if(release == "FC8")
{

  if ((res = isrpmvuln(pkg:"python-paramiko", rpm:"python-paramiko~1.7.1~3.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-paramiko", rpm:"python-paramiko~1.7.1~3.fc8", rls:"FC8")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
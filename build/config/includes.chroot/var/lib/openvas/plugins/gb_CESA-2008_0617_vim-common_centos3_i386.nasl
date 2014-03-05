###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for vim-common CESA-2008:0617 centos3 i386
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
tag_insight = "Vim (Visual editor IMproved) is an updated and improved version of the vi
  editor.

  Several input sanitization flaws were found in Vim's keyword and tag
  handling. If Vim looked up a document's maliciously crafted tag or keyword,
  it was possible to execute arbitrary code as the user running Vim.
  (CVE-2008-4101)
  
  A heap-based overflow flaw was discovered in Vim's expansion of file name
  patterns with shell wildcards. An attacker could create a specially-crafted
  file or directory name that, when opened by Vim, caused the application to
  crash or, possibly, execute arbitrary code. (CVE-2008-3432)
  
  Several input sanitization flaws were found in various Vim system
  functions. If a user opened a specially crafted file, it was possible to
  execute arbitrary code as the user running Vim. (CVE-2008-2712)
  
  Ulf H�rnhammar, of Secunia Research, discovered a format string flaw in
  Vim's help tag processor. If a user was tricked into executing the
  &quot;helptags&quot; command on malicious data, arbitrary code could be executed with
  the permissions of the user running Vim. (CVE-2007-2953)
  
  All Vim users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues.";

tag_affected = "vim-common on CentOS 3";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-November/015438.html");
  script_id(880081);
  script_version("$Revision: 15 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2008:0617");
  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3432", "CVE-2008-4101");
  script_name( "CentOS Update for vim-common CESA-2008:0617 centos3 i386");

  script_description(desc);
  script_summary("Check for the Version of vim-common");
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

  if ((res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~6.3.046~0.30E.11", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~6.3.046~0.30E.11", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~6.3.046~0.30E.11", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~6.3.046~0.30E.11", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vim", rpm:"vim~6.3.046~0.30E.11", rls:"CentOS3")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

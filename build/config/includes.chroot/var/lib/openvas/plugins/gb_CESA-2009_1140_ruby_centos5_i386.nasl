###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ruby CESA-2009:1140 centos5 i386
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
tag_insight = "Ruby is an extensible, interpreted, object-oriented, scripting language. It
  has features to process text files and to do system management tasks.

  A flaw was found in the way the Ruby POP module processed certain APOP
  authentication requests. By sending certain responses when the Ruby APOP
  module attempted to authenticate using APOP against a POP server, a remote
  attacker could, potentially, acquire certain portions of a user's
  authentication credentials. (CVE-2007-1558)
  
  It was discovered that Ruby did not properly check the return value when
  verifying X.509 certificates. This could, potentially, allow a remote
  attacker to present an invalid X.509 certificate, and have Ruby treat it as
  valid. (CVE-2009-0642)
  
  A flaw was found in the way Ruby converted BigDecimal objects to Float
  numbers. If an attacker were able to provide certain input for the
  BigDecimal object converter, they could crash an application using this
  class. (CVE-2009-1904)
  
  All Ruby users should upgrade to these updated packages, which contain
  backported patches to resolve these issues.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "ruby on CentOS 5";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-July/016025.html");
  script_id(880866);
  script_version("$Revision: 13 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2009:1140");
  script_cve_id("CVE-2007-1558", "CVE-2009-0642", "CVE-2009-1904");
  script_name("CentOS Update for ruby CESA-2009:1140 centos5 i386");

  script_description(desc);
  script_summary("Check for the Version of ruby");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:centos:centos", "login/SSH/success", "ssh/login/release");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-rdoc", rpm:"ruby-rdoc~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-ri", rpm:"ruby-ri~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.5~5.el5_3.7", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

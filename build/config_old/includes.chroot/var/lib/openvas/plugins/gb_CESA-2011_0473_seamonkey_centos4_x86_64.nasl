###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for seamonkey CESA-2011:0473 centos4 x86_64
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
tag_insight = "SeaMonkey is an open source web browser, email and newsgroup client, IRC
  chat client, and HTML editor.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could possibly lead to arbitrary code
  execution with the privileges of the user running SeaMonkey.
  (CVE-2011-0080)
  
  An arbitrary memory write flaw was found in the way SeaMonkey handled
  out-of-memory conditions. If all memory was consumed when a user visited a
  malicious web page, it could possibly lead to arbitrary code execution
  with the privileges of the user running SeaMonkey. (CVE-2011-0078)
  
  An integer overflow flaw was found in the way SeaMonkey handled the HTML
  frameset tag. A web page with a frameset tag containing large values for
  the &quot;rows&quot; and &quot;cols&quot; attributes could trigger this flaw, possibly leading
  to arbitrary code execution with the privileges of the user running
  SeaMonkey. (CVE-2011-0077)
  
  A flaw was found in the way SeaMonkey handled the HTML iframe tag. A web
  page with an iframe tag containing a specially-crafted source address could
  trigger this flaw, possibly leading to arbitrary code execution with the
  privileges of the user running SeaMonkey. (CVE-2011-0075)
  
  A flaw was found in the way SeaMonkey displayed multiple marquee elements.
  A malformed HTML document could cause SeaMonkey to execute arbitrary code
  with the privileges of the user running SeaMonkey. (CVE-2011-0074)
  
  A flaw was found in the way SeaMonkey handled the nsTreeSelection element.
  Malformed content could cause SeaMonkey to execute arbitrary code with the
  privileges of the user running SeaMonkey. (CVE-2011-0073)
  
  A use-after-free flaw was found in the way SeaMonkey appended frame and
  iframe elements to a DOM tree when the NoScript add-on was enabled.
  Malicious HTML content could cause SeaMonkey to execute arbitrary code with
  the privileges of the user running SeaMonkey. (CVE-2011-0072)
  
  All SeaMonkey users should upgrade to these updated packages, which correct
  these issues. After installing the update, SeaMonkey must be restarted for
  the changes to take effect.";

tag_affected = "seamonkey on CentOS 4";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-April/017469.html");
  script_id(881284);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:16:12 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075",
                "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "CESA", value: "2011:0473");
  script_name("CentOS Update for seamonkey CESA-2011:0473 centos4 x86_64");

  script_description(desc);
  script_summary("Check for the Version of seamonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"seamonkey", rpm:"seamonkey~1.0.9~70.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-chat", rpm:"seamonkey-chat~1.0.9~70.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-devel", rpm:"seamonkey-devel~1.0.9~70.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-dom-inspector", rpm:"seamonkey-dom-inspector~1.0.9~70.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-js-debugger", rpm:"seamonkey-js-debugger~1.0.9~70.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"seamonkey-mail", rpm:"seamonkey-mail~1.0.9~70.el4.centos", rls:"CentOS4")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
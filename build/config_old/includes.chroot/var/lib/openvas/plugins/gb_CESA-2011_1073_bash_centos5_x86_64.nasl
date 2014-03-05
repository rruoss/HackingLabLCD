###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for bash CESA-2011:1073 centos5 x86_64
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
tag_insight = "Bash is the default shell for Red Hat Enterprise Linux.

  It was found that certain scripts bundled with the Bash documentation
  created temporary files in an insecure way. A malicious, local user could
  use this flaw to conduct a symbolic link attack, allowing them to overwrite
  the contents of arbitrary files accessible to the victim running the
  scripts. (CVE-2008-5374)
  
  This update fixes the following bugs:
  
  * When using the source builtin at location &quot;.&quot;, occasionally, bash
  opted to preserve internal consistency and abort scripts. This caused
  bash to abort scripts that assigned values to read-only variables.
  This is now fixed to ensure that such scripts are now executed as
  written and not aborted. (BZ#448508)
  
  * When the tab key was pressed for auto-completion options for the typed
  text, the cursor moved to an unexpected position on a previous line if
  the prompt contained characters that cannot be viewed and a &quot;\]&quot;. This
  is now fixed to retain the cursor at the expected position at the end of
  the target line after autocomplete options correctly display. (BZ#463880)
  
  * Bash attempted to interpret the NOBITS .dynamic section of the ELF
  header. This resulted in a &quot;^D: bad ELF interpreter: No such
  file or directory&quot; message. This is fixed to ensure that the invalid
  &quot;^D&quot; does not appear in the error message. (BZ#484809)
  
  * The $RANDOM variable in Bash carried over values from a previous
  execution for later jobs. This is fixed and the $RANDOM variable
  generates a new random number for each use. (BZ#492908)
  
  * When Bash ran a shell script with an embedded null character, bash's
  source builtin parsed the script incorrectly. This is fixed and
  bash's source builtin correctly parses shell script null characters.
  (BZ#503701)
  
  * The bash manual page for &quot;trap&quot; did not mention that signals ignored upon
  entry cannot be listed later. The manual page was updated for this update
  and now specifically notes that &quot;Signals ignored upon entry to the shell
  cannot be trapped, reset or listed&quot;. (BZ#504904)
  
  * Bash's readline incorrectly displayed additional text when resizing
  the terminal window when text spanned more than one line, which caused
  incorrect display output. This is now fixed to ensure that text in more
  than one line in a resized window displays as expected. (BZ#525474)
  
  * Previously, bash incorrectly displayed &quot;Broken pipe&quot; messages for
  builtins like &quot;echo&quot; and &quot;printf&quot; when output did not succeed due to
  EPIPE. This is fixed t ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "bash on CentOS 5";
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
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2011-September/017767.html");
  script_id(881347);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:33:34 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2008-5374");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_xref(name: "CESA", value: "2011:1073");
  script_name("CentOS Update for bash CESA-2011:1073 centos5 x86_64");

  script_description(desc);
  script_summary("Check for the Version of bash");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"bash", rpm:"bash~3.2~32.el5", rls:"CentOS5")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
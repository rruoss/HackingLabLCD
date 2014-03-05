###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for quota RHSA-2013:0120-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "The quota package provides system administration tools for monitoring
  and limiting user and group disk usage on file systems.

  It was discovered that the rpc.rquotad service did not use tcp_wrappers
  correctly. Certain hosts access rules defined in '/etc/hosts.allow' and
  '/etc/hosts.deny' may not have been honored, possibly allowing remote
  attackers to bypass intended access restrictions. (CVE-2012-3417)

  This issue was discovered by the Red Hat Security Response Team.

  This update also fixes the following bugs:

  * Prior to this update, values were not properly transported via the remote
  procedure call (RPC) and interpreted by the client when querying the quota
  usage or limits for network-mounted file systems if the quota values were
  2^32 kilobytes or greater. As a consequence, the client reported mangled
  values. This update modifies the underlying code so that such values are
  correctly interpreted by the client. (BZ#667360)

  * Prior to this update, warnquota sent messages about exceeded quota limits
  from a valid domain name if the warnquota tool was enabled to send warning
  e-mails and the superuser did not change the default warnquota
  configuration. As a consequence, the recipient could reply to invalid
  addresses. This update modifies the default warnquota configuration to use
  the reserved example.com. domain. Now, warnings about exceeded quota limits
  are sent from the reserved domain that inform the superuser to change to
  the correct value. (BZ#680429)

  * Previously, quota utilities could not recognize the file system as having
  quotas enabled and refused to operate on it due to incorrect updating of
  /etc/mtab. This update prefers /proc/mounts to get a list of file systems
  with enabled quotas. Now, quota utilities recognize file systems with
  enabled quotas as expected. (BZ#689822)

  * Prior to this update, the setquota(8) tool on XFS file systems failed
  to set disk limits to values greater than 2^31 kilobytes. This update
  modifies the integer conversion in the setquota(8) tool to use a 64-bit
  variable big enough to store such values. (BZ#831520)

  All users of quota are advised to upgrade to this updated package, which
  contains backported patches to resolve these issues.";


tag_affected = "quota on Red Hat Enterprise Linux (v. 5 server)";
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
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2013-January/msg00003.html");
  script_id(870873);
  script_version("$Revision: 11 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:41:29 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-3417");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_xref(name: "RHSA", value: "2013:0120-01");
  script_name("RedHat Update for quota RHSA-2013:0120-01");

  script_description(desc);
  script_summary("Check for the Version of quota");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:redhat:enterprise_linux", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"quota", rpm:"quota~3.13~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quota-debuginfo", rpm:"quota-debuginfo~3.13~8.el5", rls:"RHENT_5")) != NULL)
  {
    security_warning(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}

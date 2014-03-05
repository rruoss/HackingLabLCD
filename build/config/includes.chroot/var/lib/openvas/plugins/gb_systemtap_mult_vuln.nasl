###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_systemtap_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# SystemTap Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_solution = "Apply the available patch from below link,
  http://sourceware.org/git/gitweb.cgi?p=systemtap.git;a=patch;h=a2d399c87a642190f08ede63dc6fc434a5a8363a

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow local users to Denial of Service and
  potentially gain escalated privileges.
  Impact Level: System.";
tag_affected = "SystemTap versions 1.1 and prior.";
tag_insight = "The flaw is due to multiple integer signedness errors in the '__get_argv()'
  and '__get_compat_argv()' functions in 'tapset/aux_syscall.stp' via a process with
  a large number of arguments.";
tag_summary = "This host has SystemTap installed and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(800294);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(38120);
  script_cve_id("CVE-2010-0411");
  script_name("SystemTap Multiple Vulnerabilities");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  script_xref(name : "URL" , value : "http://secunia.com/advisories/38426");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=559719");

  script_description(desc);
  script_summary("Check for the version of SystemTap");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_systemtap_detect.nasl");
  script_family("General");
  script_require_keys("SystemTap/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

systapVer = get_kb_item("SystemTap/Ver");
if(systapVer != NULL)
{
  if(version_is_less_equal(version:systapVer, test_version:"1.1")){
    security_warning(0);
  }
}

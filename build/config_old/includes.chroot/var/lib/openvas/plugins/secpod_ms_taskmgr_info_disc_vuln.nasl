###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_taskmgr_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# MS Windows taskmgr.exe Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.org
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
tag_impact = "Successful exploitation will let the attacker retrieve password related
  information and can cause brute force or benchmarking attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows XP SP3 and prior.
  Microsoft Windows Server 2003 SP2 and prior.";
tag_insight = "The I/O activity measurement of all processes allow to obtain sensitive
  information by reading the I/O other bytes column in taskmgr.exe to
  estimate the number of characters that a different user entered at a
  password prompt through 'runas.exe'.";
tag_solution = "No solution or patch is available as of 03rd February, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en/us/default.aspx";
tag_summary = "This host is running Windows Operating System and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(900302);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-03 15:40:18 +0100 (Tue, 03 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0320");
  script_bugtraq_id(33440);
  script_name("MS Windows taskmgr.exe Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.unifiedds.com/?p=44");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/500393/100/0/threaded");

  script_description(desc);
  script_summary("Check for the existence of Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("secpod_reg.inc");

exit(0); ## plugin may results to FP

if(hotfix_check_sp(xp:4, win2003:3) > 0){
  security_warning(0);
}

###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: gb_xnview_code_exec_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# XnView File Search Path Executable File Injection Vulnerability (Windows)
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This host has XnView installed and is prone to executable file
  injection vulnerability.

  Vulnerabilities Insight:
  The flaw is caused by an untrusted search path vulnerability when loading
  executables.";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code on the
  system with elevated privileges.
  Impact Level: System/Application";
tag_affected = "XnView versions prior to 1.98.1 on windows.";
tag_solution = "Update to XnView version 1.98.1 or later.
  For updates refer to http://www.xnview.com/";

if(description)
{
  script_id(802309);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_cve_id("CVE-2011-1338");
  script_bugtraq_id(48562);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("XnView File Search Path Executable File Injection Vulnerability (Windows)");
  desc = "
  Summary:
  " + tag_summary + "
  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://osvdb.org/73619");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45127");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68369");

  script_description(desc);
  script_summary("Check for the version of XnView");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_require_keys("XnView/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

## Get XnView from KB
xnviewVer = get_kb_item("XnView/Win/Ver");

if(xnviewVer != NULL)
{
  ## Check for XnView version less than 1.98.1
  if(version_is_less(version:xnviewVer, test_version:"1.98.1")){
   security_hole(0);
  }
}

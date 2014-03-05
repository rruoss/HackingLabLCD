###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pgp_desktop_local_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PGP Desktop Local Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to execute arbitrary code with
  system privileges or to crash the application.
  Impact Level: Application.";
tag_affected = "PGP Desktop prior to version 9.10 on Windows.";
tag_insight = "IOCTL handler in 'pgpdisk.sys' and 'pgpwded.sys' files does not adequately
  validate buffer data associated with the Irp object.";
tag_solution = "Upgrade to PGP Desktop 9.10
  http://www.pgp.com/downloads/desktoptrial/desktoptrial2.html";
tag_summary = "This host has PGP Desktop is installed and is prone to Denial of Service
  vulnerability.";

if(description)
{
  script_id(800600);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-0681");
  script_bugtraq_id(34490);
  script_name("PGP Desktop Local Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33310/");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2009-01");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/502633");

  script_description(desc);
  script_summary("Check for the version of PGP Desktop");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_pgp_desktop_detect_win.nasl");
  script_require_keys("PGPDesktop/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

pgpVer = get_kb_item("PGPDesktop/Win/Ver");
if(!pgpVer){
  exit(0);
}

# Check for version < 9.10
if(version_is_less(version:pgpVer, test_version:"9.10.0.500")){
  security_hole(0);
}

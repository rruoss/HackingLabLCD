##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaspersky_av_2010_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Kaspersky Anti-Virus 2010 'kl1.sys' Driver DoS Vulnerability
#
# Authors:
# Veerendra GG <veernedragg@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code with
  elevated privileges or cause the kernel to crash.
  Impact Level: System/Application";
tag_affected = "Kaspersky Anti-Virus 2010 before 9.0.0.736 on Windows.";
tag_insight = "The flaw is due to NULL pointer dereference in 'kl1.sys' driver via a
  specially-crafted IOCTL 0x0022c008 call.";
tag_solution = "Update to version 9.0.0.736 or later,
  For updates refer to http://www.kaspersky.com/downloads";
tag_summary = "The host is installed with Kaspersky Anti-Virus 2010 and is prone
  to Denial of Service vulnerability.";

if(description)
{
  script_id(800154);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-05 12:49:16 +0100 (Sat, 05 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-4114");
  script_bugtraq_id(37044);
  script_name("Kaspersky Anti-Virus 2010 'kl1.sys' Driver DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37398");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54309");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/507933/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Kaspersky Anti-Virus");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_kaspersky_av_detect.nasl");
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

## Get Version from KB
kavVer = get_kb_item("Kaspersky/AV/Ver");
if(kavVer != NULL)
{
  ## Kaspersky Anti-Virus 2010 before 9.0.0.736
  if(version_in_range(version:kavVer, test_version:"9.0", test_version2:"9.0.0.735")){
    security_warning(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_icq_xss_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# ICQ Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_insight = "The flaw is due to lack of input validation and output sanitisation
  of the profile entries.

  Impact
  Successful exploitation will allow remote attackers to hijack session IDs of
  users and leverage the vulnerability to increase the attack vector to the
  underlying software and operating system of the victim.

  Impact Level: Application.

  Affected Software:
  ICQ version 7.5 and prior.";

tag_solution = "No solution or patch is available as of 27th July, 2011. Information
  regarding this issue will be updated once the solution details are available
  For updates refer to http://www.icq.com/en";
tag_summary = "This host is installed with ICQ and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(902702);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("ICQ Cross Site Scripting Vulnerability");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "
  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/103430/icqcli-xss.txt");

  script_description(desc);
  script_summary("Check for the version of ICQ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_icq_detect.nasl");
  script_require_keys("ICQ/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}

include("version_func.inc");

## Get the version from KB
icqVer = get_kb_item("ICQ/Ver");
if(!icqVer){
  exit(0);
}

## Check for ICQ version less than or equal to 7.5
if(version_is_less_equal(version:icqVer, test_version:"7.5.0.5255")){
  security_warning(0);
}

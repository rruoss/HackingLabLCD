###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_msn_n_xmpp_dos_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Pidgin MSN and XMPP Denial of Service Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to crash the affected
  application.
  Impact Level: Application";
tag_affected = "Pidgin version prior 2.10.4 on Windows";
tag_insight = "- An error in 'msn_message_parse_payload()' function handling messages with
    certain characters or character encodings can be exploited to cause a
    crash.
  - An error in SOCKS5 proxy handling code can be exploited to dereference an
    invalid pointer and cause a crash by sending multiple specially crafted
    file transfer requests.";
tag_solution = "Upgrade to Pidgin version 2.10.4 or later,
  For updates refer to http://pidgin.im/download";
tag_summary = "This host has installed with Pidgin and is prone to denial of
  service vulnerabilities.";

if(description)
{
  script_id(802906);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2318", "CVE-2012-2214");
  script_bugtraq_id(53400, 53706);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-04 16:00:59 +0530 (Wed, 04 Jul 2012)");
  script_name("Pidgin MSN and XMPP Denial of Service Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49036/");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=63");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=62");
  script_xref(name : "URL" , value : "http://hg.pidgin.im/pidgin/main/rev/4d6bcb4f4ea4");

  script_description(desc);
  script_summary("Check for the Version of Pidgin on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_require_keys("Pidgin/Win/Ver");
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

## Variable initialization
pidginVer = "";

pidginVer = get_kb_item("Pidgin/Win/Ver");
if(pidginVer)
{
  if(version_is_less(version:pidginVer, test_version:"2.10.4")){
    security_warning(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_live_msngr_charset_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft MSN Live Messneger Denial of Service Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can cause denial of service.

  Impact level: Application/System";

tag_affected = "Microsoft Live Messenger version 14.0.8064.206 and prior.";
tag_insight = "This flaw is due to failure in handling charset of the message which user
  sends.";
tag_solution = "Solution/patch not available as on 20th February 2009. For updates
  refer, http://www.messenger.live.com";
tag_summary = "This host is running Microsoft MSN Live Messenger and is prone
  to Denial of Service Vulnerability.";

if(description)
{
  script_id(900461);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_bugtraq_id(33825);
  script_cve_id("CVE-2009-0647");
  script_name("Microsoft MSN Live Messneger Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/501043");

  script_description(desc);
  script_summary("Check for the version of Live Messenger");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_ms_win_live_messenger_detect.nasl");
  script_require_keys("MS/LiveMessenger/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

liveVer = get_kb_item("MS/LiveMessenger/Ver");
if(!liveVer){
  exit(0);
}

# Grep for 'msnmsgr.exe' version 14.0.8064.0206 or prior.
if(version_is_less_equal(version:liveVer, test_version:"14.0.8064.0206")){
  security_warning(0);
}

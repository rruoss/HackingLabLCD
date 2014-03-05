###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_groupshield_exchange_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# McAfee GroupShield for Exchange X-Header Security Bypass Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploits will let the attacker craft malicious contents inside the
  X-Header and can bypass antivirus detection and launch further attacks into
  the affected system.
  Impact Level: System";
tag_affected = "McAfee GroupShield for Exchange version 6.0.616.102 and prior.";
tag_insight = "This flaw is due to failure in scanning X-Headers while sending mail
  messages.";
tag_solution = "No solution or patch is available as of 22nd May, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.mcafee.com/us/enterprise/products/anti_virus/email_servers/groupshield_microsoft_exchange.html";
tag_summary = "This host is installed McAfee GroupShield for Microsoft Exchange and
  is prone to X-Header Security Bypass Vulnerability.";

if(description)
{
  script_id(800619);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-22 10:20:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1491");
  script_bugtraq_id(34949);
  script_name("McAfee GroupShield for Exchange X-Header Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50354");
  script_xref(name : "URL" , value : "http://www.nmrc.org/~thegnome/blog/apr09");

  script_description(desc);
  script_summary("Check for the version of McAfee GroupShield Exchange");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("gb_mcafee_groupshield_detect.nasl");
  script_require_keys("McAfee/GroupShield/Exchange/Ver");
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

groupVer = get_kb_item("McAfee/GroupShield/Exchange/Ver");
if(groupVer != NULL)
{
  # Grep for McAfee Groupshield for Exchange version 6.0.616.102
  if(version_is_less_equal(version:groupVer, test_version:"6.0.616.102")){
    security_hole(0);
  }
}

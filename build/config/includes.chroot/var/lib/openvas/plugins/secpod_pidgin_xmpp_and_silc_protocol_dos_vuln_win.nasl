###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_xmpp_and_silc_protocol_dos_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Pidgin XMPP And SILC Protocols Denial of Service Vulnerabilities (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to cause the application
  to crash, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "Pidgin versions prior to 2.10.1";
tag_insight = "Multiplw flaws are due to
  - An error in the silc_channel_message function in ops.c in the SILC
    protocol plugin in libpurple, which fails to validate that a piece of text
    was UTF-8 when receiving various incoming messages.
  - An error in the XMPP protocol plugin in libpurple, which fails to ensure
    that the incoming message contained all required fields when receiving
    various stanzas related to voice and video chat.
  - An error in the family_feedbag.c in the oscar protocol plugin, which fails
    to validate that a piece of text was UTF-8 when receiving various incoming
    messages.";
tag_solution = "Upgrade to Pidgin version 2.10.1 or later,
  For updates refer to http://pidgin.im/download/windows/";
tag_summary = "This host is installed with Pidgin and is prone to denial of
  service vulnerabilities.";

if(description)
{
  script_id(902650);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4602", "CVE-2011-4603", "CVE-2011-4601");
  script_bugtraq_id(51070, 51074);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-21 11:02:55 +0530 (Wed, 21 Dec 2011)");
  script_name("Pidgin XMPP And SILC Protocols Denial of Service Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77750");
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/77751");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=57");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=58");
  script_xref(name : "URL" , value : "http://pidgin.im/news/security/?id=59");

  script_description(desc);
  script_summary("Check for the version of Pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Get Pidgin Version from KB
pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  ## Check for Pidgin Versions Prior to 2.10.1
  if(version_is_less(version:pidginVer, test_version:"2.10.1")){
    security_warning(0);
  }
}

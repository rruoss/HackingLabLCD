###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_silc_prdts_nickname_format_string_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# SILC Client Nickname Field Format String Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_solution = "Apply the patch or upgrade to SILC Client 1.1.8.
  http://silcnet.org/
  http://www.securityfocus.com/bid/35940/solution

  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****";

tag_impact = "Attackers can exploit this iisue to execute arbitrary code in the
  context of the affected application and compromise the system.
  Impact Level: Application/System";
tag_affected = "SILC Client prior to 1.1.8
  SILC Toolkit prior to 1.1.10.";
tag_insight = "A format string error occurs in 'lib/silcclient/client_entry.c' while
  processing format string specifiers in the nickname field.";
tag_summary = "This host has SILC Client/Toolkit installed, and is prone
  to Format String vulnerability.";

if(description)
{
  script_id(900951);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3051");
  script_bugtraq_id(35940);
  script_name("SILC Client Nickname Field Format String Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36134");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2150");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/09/03/5");

  script_description(desc);
  script_summary("Check for the version of SILC Client & Toolkit");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_silc_prdts_detect.nasl");
  script_require_keys("SILC/Client/Ver", "SILC/Toolkit/Ver");
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

# Check if the SILC-Client version is prior to 1.1.8
clntVer = get_kb_item("SILC/Client/Ver");
if(clntVer)
{
  if(version_is_less(version:clntVer, test_version:"1.1.8"))
  {
    security_hole(0);
    exit(0);
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_gupnp_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# GUPnP Message Handling Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation via specially crafted messages will allow attackers to
  run arbitrary code, crash the application and cause cause denial of service.
  Impact Level: System/Application";
tag_affected = "GUPnP Version 0.12.7 and prior.";
tag_insight = "The flaw is due to an error when processing subscription or control
  messages with an empty content.";
tag_solution = "Upgrade to version 0.12.8 or later.
  http://www.gupnp.org/sources/";
tag_summary = "This host has installed GUPnP is prone to Denial Of Service
  Vulnerability";

if(description)
{
  script_id(900682);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2174");
  script_bugtraq_id(35390);
  script_name("GUPnP Message Handling Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/55128");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35482");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1597");

  script_description(desc);
  script_summary("Checks for the Version of GUPnP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_gupnp_detect.nasl");
  script_require_keys("GUPnP/Ver");
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

gupnpVer = get_kb_item("GUPnP/Ver");
if(gupnpVer != NULL)
{
  if(version_is_less(version:gupnpVer, test_version:"0.12.8")){
    security_warning(0);
  }
}

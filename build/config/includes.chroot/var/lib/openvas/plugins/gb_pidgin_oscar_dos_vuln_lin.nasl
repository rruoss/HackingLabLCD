###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pidgin_oscar_dos_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Pidgin OSCAR Protocol Denial Of Service Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to cause a application crash.
  Impact Level: Application";
tag_affected = "Pidgin version prior to 2.5.8 on Linux";
tag_insight = "Error in OSCAR protocol implementation leads to the application misinterpreting 
  the ICQWebMessage message type as ICQSMS message type via a crafted ICQ web 
  message that triggers allocation of a large amount of memory.";
tag_solution = "Upgrade to Pidgin version 2.5.8,
  http://pidgin.im/download";
tag_summary = "This host has installed Pidgin and is prone to Denial of Service
  vulnerability.";

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.800824";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1889");
  script_bugtraq_id(35530);
  script_name("Pidgin OSCAR Protocol Denial Of Service Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35652");
  script_xref(name : "URL" , value : "http://developer.pidgin.im/ticket/9483");
  script_xref(name : "URL" , value : "http://pidgin.im/pipermail/devel/2009-May/008227.html");

  script_description(desc);
  script_summary("Check for the Version of Pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_lin.nasl");
  script_require_keys("Pidgin/Lin/Ver");
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
include("host_details.inc");

ver = get_app_version(cpe:"cpe:/a:pidgin:pidgin", nvt:SCRIPT_OID);
if(version_is_less(version:ver, test_version:"2.5.8")){
  security_warning(0);
}

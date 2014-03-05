###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_prv_esc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Adobe Flash Media Server Privilege Escalation Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful attack could result in execution of crafted RPC Calls to the
  ActionScript file and cause injection of remote procedures into the context
  of the affected system.
  Impact Level: System";
tag_affected = "Adobe Flash Media Server before 3.0.4, 3.5.x before 3.5.2 on all platforms.";
tag_insight = "This flaw is caused while executing RPC calls made to an ActionScript file
  running under Flash Media Server.";
tag_solution = "Upgrade to Adobe Flash Media Server 3.5.2 or 3.0.4 or greater.
  http://www.adobe.com/downloads";
tag_summary = "This host has Adobe Flash Media Server installed and is prone to
  Privilege Escalation vulnerability.";

if(description)
{
  script_id(800560);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1365");
  script_bugtraq_id(34790);
  script_name("Adobe Flash Media Server Privilege Escalation Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb09-05.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Media Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_fms_detect.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

mediaPort = get_http_port(default:1111);
if(!mediaPort){
  exit(0);
}

fmsVer = get_kb_item("www/" + mediaPort + "/Adobe/FMS");
if(fmsVer == NULL){
  exit(0);
}

if(version_in_range(version:fmsVer, test_version:"3.5", test_version2:"3.5.1")||
    version_is_less(version:fmsVer, test_version:"3.0.4")){
  security_hole(mediaPort);
}

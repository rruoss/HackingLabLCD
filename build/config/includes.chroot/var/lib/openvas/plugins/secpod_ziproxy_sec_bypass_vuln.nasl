###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ziproxy_sec_bypass_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Ziproxy Security Bypass Vulnerability
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
tag_impact = "This can be exploited to restrict websites or bypass a browser's
  security context protection mechanism by sending HTTP requests with
  forged HTTP Host header.
  Impact Level: System/Application";
tag_affected = "Ziproxy version 2.6.0 and prior on Linux.";
tag_insight = "This vulnerability arises because ziproxy depends on HTTP Host headers
  to determine the remote endpoints while acting as a transparent proxy.";
tag_solution = "Upgrade to Ziproxy version 3.1.0 or later,
  For updates refer to http://ziproxy.sourceforge.net/";
tag_summary = "This host is running Ziproxy server and is prone to security
  bypass vulnerability.";

if(description)
{
  script_id(900523);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-26 11:19:12 +0100 (Thu, 26 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_tag(name:"cvss_temporal", value:"6.1");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-0804");
  script_bugtraq_id(33858);
  script_name("Ziproxy Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34018/");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/435052");

  script_description(desc);
  script_summary("Check for the version of Ziproxy");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Privilege escalation");
  script_dependencies("secpod_ziproxy_server_detect.nasl");
  script_require_ports("Services/www", 8080);
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

zipPort = get_kb_item("Services/www");
if(!zipPort){
  exit(0);
}

ziproxyVer = get_kb_item("www/" + zipPort + "/Ziproxy");
if(!ziproxyVer){
  exit(0);
}

if(version_is_less_equal(version:ziproxyVer, test_version:"2.6.0")){
  security_hole(zipPort);
}

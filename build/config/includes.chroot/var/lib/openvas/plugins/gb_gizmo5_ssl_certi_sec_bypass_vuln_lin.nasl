###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gizmo5_ssl_certi_sec_bypass_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Gizmo5 SSL Certificate Validation Security Bypass Vulnerability (Linux)
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information that could be used to launch further attacks against the victim's
  system.
  Impact Level: System/Application";
tag_affected = "Gizmo5 version 3.1.0.79 and prior on Linux";
tag_insight = "Error exists due to improper verification of SSL certificates which can be
  exploited by using man-in-the-middle techniques to spoof SSL certificates
  and redirect a user to a malicious Web site that would appear to be trusted.";
tag_solution = "No solution or patch is available as of 14th July, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://gizmo5.com/pc";
tag_summary = "This host is installed with Gizmo5 and is prone to Security Bypass
  vulnerability.";

if(description)
{
  script_id(800833);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2381");
  script_bugtraq_id(35508);
  script_name("Gizmo5 SSL Certificate Validation Security Bypass Vulnerability (Linux) ");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35628");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51399");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504572/100/0/threaded");

  script_description(desc);
  script_summary("Check for the Version of Gizmo5");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gizmo5_detect_lin.nasl");
  script_require_keys("Gizmo5/Linux/Ver");
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

foreach gizmoPort (make_list(5004, 5005))
{
  if(get_udp_port_state(gizmoPort))
  {
    gizmoVer = get_kb_item("Gizmo5/Linux/Ver");
    if(gizmoVer == NULL){
      exit(0);
    }

    if(version_is_less_equal(version:gizmoVer, test_version:"3.1.0.79")){
      security_warning(port:gizmoPort, proto:"udp");
    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_GlassFish_prev_escl_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Java GlassFish Server Privilege Escalation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_solution = "Apply the security updates.
  http://www.oracle.com/technetwork/topics/security/cpujan2011-194091.html

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow local attackers to affect confidentiality
  and integrity via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Oracle GlassFish version 2.1, 2.1.1 and 3.0.1";
tag_insight = "The issue is caused by an unspecified error related to the Java Message
  Service, which could allow local attackers to disclose or manipulate certain
  information, or create a denial of service condition.";
tag_summary = "The host is running GlassFish Server and is prone to privilege
  escalation vulnerability.";

if(description)
{
  script_id(902286);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-07 15:21:16 +0100 (Mon, 07 Feb 2011)");
  script_cve_id("CVE-2010-4438");
  script_bugtraq_id(45890);
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Oracle Java GlassFish Server Privilege Escalation Vulnerability");
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

  script_xref(name : "URL" , value : "http://osvdb.org/70572");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42988");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64813");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0155");

  script_description(desc);
  script_summary("Check for the version of Oracle Java GlassFish Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("GlassFish_detect.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Check for the default port
if(!port = get_http_port(default:8080)){
  port = 8080;
}

## Check port status
if(!get_port_state(port)){
  exit(0);
}

## Get the version form KB
vers = get_kb_item(string("www/", port, "/GlassFish"));
if(!isnull(vers))
{
  if(version_is_equal(version: vers, test_version:"3.0.1") ||
     version_in_range(version: vers, test_version:"2.1", test_version2:"2.1.1")){
    security_hole(port:port);
  }
}

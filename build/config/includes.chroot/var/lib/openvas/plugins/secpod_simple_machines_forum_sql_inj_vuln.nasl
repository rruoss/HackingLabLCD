###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_simple_machines_forum_sql_inj_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Simple Machines Forum SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code,
  and can view, add, modify or delete information in the back-end database.
  Impact Level: System/Application.";
tag_affected = "Simple Machines Forum 1.1.4 and prior";
tag_insight = "Error exists while sending an specially crafted SQL statements into load.php
  when setting the db_character_set parameter to a multibyte character which
  causes the addslashes PHP function to generate a \(backslash) sequence that
  does not quote the '(single quote) character, as demonstrated via a manlabels
  action to index.php.";
tag_solution = "No solution or patch is available as of 29th April, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.simplemachines.org/";
tag_summary = "The host is installed with Simple Machines Forum and is prone
  to SQL Injection Vulnerability.";

if(description)
{
  script_id(900544);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-6741");
  script_bugtraq_id(29734);
  script_name("Simple Machines Forum SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5826");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/43118");

  script_description(desc);
  script_summary("Check for the version of Simple Machines Forum");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_require_ports("Services/www", 80);
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

httpPort = get_http_port(default:80);
if(!httpPort){
  exit(0);
}

if(!get_port_state(httpPort)){
  exit(0);
}

ver = get_kb_item("www/" + httpPort + "/SMF");
ver = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(ver[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:ver[1], test_version:"1.1.4")){
 security_hole(httpPort);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simple_machines_forum_session_hijacking_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Simple Machines Forum Session Hijacking Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to obtain sensitive
  information such as user's session credentials and may aid in further
  attacks.
  Impact Level: Application";
tag_affected = "Simple Machines Forum (SMF) 2.0";
tag_insight = "The flaw exists due to improper handling of user's sessions, allowing a
  remote attacker to hijack a valid user's session via a specially crafted
  link.";
tag_solution = "No solution or patch is available as of 16th September 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.simplemachines.org/";
tag_summary = "The host is installed with Simple Machines Forum and is prone
  to session hijacking vulnerability.";

if(description)
{
  script_id(802334);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_bugtraq_id(49078);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Simple Machines Forum Session Hijacking Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/69056");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17637/");

  script_description(desc);
  script_summary("Check for the version of Simple Machines Forum");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

## Get the default port
smfPort = get_http_port(default:80);
if(!smfPort){
  exit(0);
}

## Get the version From kb
ver = get_version_from_kb(port:smfPort, app:"SMF");
if(!ver){
  exit(0);
}

if(version_is_equal(version:ver, test_version:"2.0")){
  security_warning(smfPort);
}

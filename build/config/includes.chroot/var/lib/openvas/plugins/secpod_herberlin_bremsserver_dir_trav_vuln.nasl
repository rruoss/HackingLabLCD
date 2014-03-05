###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_herberlin_bremsserver_dir_trav_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Herberlin Bremsserver Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Herberlin Bremsserver Version 3.0";
tag_insight = "The flaw is due to improper validation of URI containing ../(dot dot)
  sequences, which allows attackers to read arbitrary files via directory
  traversal attacks.";
tag_solution = "No solution or patch is available as of 18th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://tools.herberlin.de/bremsserver/index.shtml";
tag_summary = "The host is running Herberlin Bremsserver and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(902587);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-18 12:12:12 +0530 (Fri, 18 Nov 2011)");
  script_name("Herberlin Bremsserver Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://tools.herberlin.de/bremsserver/index.shtml");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107070/HerberlinBremsserver3.0-233.py.txt");
  script_xref(name : "URL" , value : "http://www.autosectools.com/Advisory/Herberlin-Bremsserver-3.0-Directory-Traversal-233");

  script_description(desc);
  script_summary("Determine if Herberlin Bremsserver is vulnerable to Directory Traversal Attack");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web Servers");
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
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Confirm the application before trying exploit
banner = get_http_banner(port: port);
if("Server: Herberlin Bremsserver" >!< banner) {
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
  ## Construct Directory Traversal Attack
  url = string(crap(data:"/..", length:49), files[file]);

  ## Try exploit and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, pattern:file))
  {
    security_warning(port);
    exit(0);
  }
}

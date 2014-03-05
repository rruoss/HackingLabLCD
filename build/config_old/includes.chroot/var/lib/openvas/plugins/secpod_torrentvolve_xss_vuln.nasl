###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_torrentvolve_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TorrentVolve archive.php XSS Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to delete arbitrary files
  on the affected system if register_globals is enabled.

  Impact level: Application";

tag_affected = "TorrentVolve 1.4 and prior.";
tag_insight = "The flaw occurs because archive.php does not sanitise the data passed into
  'deleteTorrent' parameter before being returned to the user.";
tag_solution = "No solution or patch is available as of 25th June, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/torrentvolve/";
tag_summary = "This host is running TorrentVolve and is prone to Cross Site
  Scripting vulnerability.";

if(description)
{
  script_id(900577);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2101");
  script_name("TorrentVolve archive.php XSS Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8931");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51088");

  script_description(desc);
  script_summary("Check for version of TorrentVolve");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_torrentvolve_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

tvPort = get_http_port(default:80);
if(!tvPort){
  exit(0);
}

tvVer = get_kb_item("www/" + tvPort + "/TorrentVolve");
tvVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tvVer);
if(tvVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:tvVer[1], test_version:"1.4")){
  security_hole(tvPort);
}
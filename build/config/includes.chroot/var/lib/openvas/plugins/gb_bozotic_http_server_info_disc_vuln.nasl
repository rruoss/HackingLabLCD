###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bozotic_http_server_info_disc_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# bozotic HTTP server Information Disclosure Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to determine the existence of a
  user and potentially disclose the user's files.
  Impact Level: Application";
tag_affected = "bozotic HTTP server (aka bozohttpd) versions before 20100621.";
tag_insight = "The server is not properly handling requests to a user's public_html folder
  while the folder does not exist. This can be exploited to determine the
  existence of user accounts via multiple requests for URIs beginning with
  /~ sequences.";
tag_solution = "Upgrade to bozotic HTTP server version 20100621 or later,
  For updates refer to http://www.eterna.com.au/bozohttpd/";
tag_summary = "This host is running bozotic HTTP server and is prone to information
  disclosure vulnerability.";

if(description)
{
  script_id(801246);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_cve_id("CVE-2010-2320");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("bozotic HTTP server Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40737");
  script_xref(name : "URL" , value : "http://www.eterna.com.au/bozohttpd/CHANGES");
  script_xref(name : "URL" , value : "http://security-tracker.debian.org/tracker/CVE-2010-2320");

  script_description(desc);
  script_summary("Check for the  bozotic HTTP server version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_bozotic_http_server_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/bozohttpd");
if(ver != NULL)
{
  ## Check for vulnerable bozohttpd versions
  if(version_is_less(version:ver, test_version:"20100621")) {
     security_warning(port);
  }
}

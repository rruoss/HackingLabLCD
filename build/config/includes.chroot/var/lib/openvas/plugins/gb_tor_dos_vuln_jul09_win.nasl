###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tor_dos_vuln_jul09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Tor Denial Of Service Vulnerability - July09 (Win)
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
tag_impact = "Successful exploitation will allow attackers to cause Denial of Service.

  Impact level: Application";

tag_affected = "Tor version 0.2.x before 0.2.0.35 on Windows.";
tag_insight = "Error exists while parsing certain malformed router descriptors and can be
  exploited to crash Tor via specially crafted router descriptors.";
tag_solution = "Upgrade to version 0.2.0.35 or later
  http://www.torproject.org/download.html.en";
tag_summary = "This host is installed with Tor and is prone to Denial Of Service
  vulnerability.";

if(description)
{
  script_id(800839);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2425");
  script_bugtraq_id(35505);
  script_name("Tor Denial Of Service Vulnerability - July09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35546");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51376");
  script_xref(name : "URL" , value : "http://archives.seul.org/or/announce/Jun-2009/msg00000.html");

  script_description(desc);
  script_summary("Check for the version of Tor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_tor_detect_win.nasl");
  script_require_keys("Tor/Win/Ver");
  script_require_ports("Services/www");
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

foreach torPort (make_list(9050, 9051, 8118))
{
  if(get_port_state(torPort))
  {
    sndReq = string("GET / HTTP/1.1", "\r\n",
                    "Host: ", get_host_name(), "\r\n\r\n");
    rcvRes = http_send_recv(port:torPort, data:sndReq);

    if(egrep(pattern:"<a\ href=?[^?]+:\/\/www\.torproject\.org",
             string:rcvRes) && "Tor" >< rcvRes)
    {
      torVer = get_kb_item("Tor/Win/Ver");
      torVer = ereg_replace(pattern:"-", replace:".", string:torVer);
      if(torVer == NULL){
        exit(0);
      }

      # Check for Tor version 0.2 < 0.2.0.35
      if(version_in_range(version:torVer, test_version:"0.2",
                                          test_version2:"0.2.0.34.alpha"))
      {
        security_warning(torPort);
        exit(0);
      }
    }
  }
}

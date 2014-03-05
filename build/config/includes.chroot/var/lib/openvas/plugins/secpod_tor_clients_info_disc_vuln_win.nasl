###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tor_clients_info_disc_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Tor Clients Information Disclosure Vulnerability (win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to obtain client IP information
  that can help them launch further attacks.

  Impact level: Application";

tag_affected = "Tor version 0.2.2.x before 0.2.2.7-alpha on Windows.";
tag_insight = "This issue is due to directory mirror which does not prevent logging of the
  client IP address upon detection of erroneous client behavior, which might make
  it easier for local users to discover the identities of clients by reading log
  files.";
tag_solution = "Upgrade to version 0.2.2.7-alpha
  http://www.torproject.org/download.html.en";
tag_summary = "This host is installed with Tor and is prone to Information Disclosure
  vulnerability.";

if(description)
{
  script_id(902102);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0384");
  script_name("Tor Clients Information Disclosure Vulnerability (win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38198");
  script_xref(name : "URL" , value : "http://archives.seul.org/or/announce/Jan-2010/msg00000.html");

  script_description(desc);
  script_summary("Check for the version of Tor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_tor_detect_win.nasl");
  script_require_keys("Tor/Win/Ver");
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

torVer = get_kb_item("Tor/Win/Ver");
if(torVer == NULL){
  exit(0);
}

foreach torPort (make_list(9050, 9051, 8118))
{
  if(get_port_state(torPort))
  {
    sndReq = string("GET / HTTP/1.1", "\r\n",
                    "Host: ", get_host_name(), "\r\n\r\n");
    rcvRes = http_send_recv(port:torPort, data:sndReq);
    if(!isnull(rcvRes) && "Tor is" >< rcvRes)
    {
      torVer = ereg_replace(pattern:"-", replace:".", string:torVer);
      if(torVer =~ "^0\.2\.2.*")
      {
        if(version_is_less(version:torVer, test_version:"0.2.2.7.alpha"))
        {
          security_warning(torPort);
          exit(0);
        }
      }
    }
  }
}

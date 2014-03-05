###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_torrent_trader_classic_mult_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TorrentTrader Classic Multiple Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to inject and execute
  arbitrary SQL queries via malicious SQL code, and can gain sensitive
  information about remote system user credentials and database.

  Impact level: Application/System";

tag_affected = "TorrentTrader Classic version 1.09 and prior.";
tag_insight = "Multiple flaws due to,improper validation of user-supplied input data to
  different parametes and Access to the '.php' scripts are not properly
  restricted.";
tag_solution = "Upgrade to TorrentTrader Classic version 2.0.6 or later
  For updates refer to http://sourceforge.net/projects/torrenttrader";
tag_summary = "This host is running TorrentTrader Classic and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800522);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2156", "CVE-2009-2157", "CVE-2009-2158",
                "CVE-2009-2159", "CVE-2009-2160", "CVE-2009-2161");
  script_bugtraq_id(35369);
  script_name("TorrentTrader Classic Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35456");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/504294/100/0/threaded");

  script_description(desc);
  script_summary("Check for Attack string and TorrentTrader Classic Version");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_torrent_trader_classic_detect.nasl");
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

ttcPort = get_http_port(default:80);
if(!ttcPort){
  exit(0);
}

ttcVer = get_kb_item("www/" + ttcPort + "/TorrentTraderClassic");
ttcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ttcVer);

if((ttcVer[2] != NULL) && (!safe_checks()))
{
  sndReq = http_get(item:string(ttcVer[2],"/upload/browse.php" +
                           "?wherecatin=waraxe"), port:ttcPort);
  rcvRes = http_send_recv(port:ttcPort, data:sndReq);
  if("Unknown column 'waraxe' in 'where clause'" >< rcvRes)
  {
    security_hole(ttcPort);
    exit(0);
  }
}

if(ttcVer[1] != NULL)
{
  if(version_is_less_equal(version:ttcVer[1], test_version:"1.09")){
    security_hole(ttcPort);
   }
}

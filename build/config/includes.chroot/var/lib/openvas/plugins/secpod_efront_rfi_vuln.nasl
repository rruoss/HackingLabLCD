##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_efront_rfi_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# eFront 'database.php' Remote File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code on the
  vulnerable Web server.

  Impact level: Application.";

tag_solution = "Apply the patch from below link.
  http://svn.efrontlearning.net/repos/efront/trunc/libraries/database.php

  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****";

tag_affected = "eFront version 3.5.4 and prior.";
tag_insight = "The flaw is due to improper validation of user supplied data and can be
  exploited via 'path' parameter in 'libraries/database.php' to include and
  execute remote files on the affected system.";
tag_summary = "This host is running eFront and is prone to Remote File Inclusion
  vulnerability.";

if(description)
{
  script_id(901045);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-31 09:54:01 +0100 (Sat, 31 Oct 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3660");
  script_bugtraq_id(36411);
  script_name("eFront 'database.php' Remote File Inclusion Vulnerability");
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


  script_description(desc);
  script_summary("Check the version and attempt a mild attack on eFront");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_efront_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9681");
  script_xref(name : "URL" , value : "http://forum.efrontlearning.net/viewtopic.php?f=1&amp;t=1354&amp;p=7174#p7174");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

efrontPort = get_http_port(default:80);
if(!efrontPort){
  exit(0);
}

efrontVer = get_kb_item("www/" + efrontPort + "/eFront");
efrontVer = eregmatch(pattern:"^(.+) under (/.*)$", string:efrontVer);

if((efrontVer[2] != NULL) && (!safe_checks()))
{
  sndReq = http_get(item:string(efrontVer[2], "/libraries/database.php"),
                    port:efrontPort);
  rcvRes = http_send_recv(port:efrontPort, data:sndReq);
  if("403 Forbidden" >!<  rcvRes)
  {
    sndReq = http_get(item:string(efrontVer[2], "/libraries/database.php?"+
             "path=xyz/OpenVAS-RemoteFileInclusion.txt"), port:efrontPort);
    rcvRes = http_send_recv(port:efrontPort, data:sndReq);

    if("xyz/OpenVAS-RemoteFileInclusion.txtadodb/adodb.inc.php" >< rcvRes)
    {
      security_hole(efrontPort);
      exit(0);
    }
  }
}

if(efrontVer[1] != NULL)
{
  if(version_is_less_equal(version:efrontVer[1], test_version:"3.5.4")){
    security_hole(efrontPort);
  }
}

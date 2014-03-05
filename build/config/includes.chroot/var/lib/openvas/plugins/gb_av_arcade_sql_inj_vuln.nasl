##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_av_arcade_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# AV Arcade 'ava_code' Cookie Parameter SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to bypass security
  restrictions and gain unauthorized administrative access to the vulnerable
  application.
  Impact Level: Application.";
tag_affected = "AV Scripts AV Arcade version 3.0";

tag_insight = "The flaws are due to an improper validation of authentication cookies
  in the 'index.php' script, when processing the 'ava_code' cookie parameter.";
tag_solution = "No solution or patch is available as of 09th August, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.avscripts.net/avarcade/freearcadescript/";
tag_summary = "This host is running AV Arcade and is prone SQL injection
  vulnerability.";

if(description)
{
  script_id(801396);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2933");
  script_bugtraq_id(42023);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("AV Arcade 'ava_code' Cookie Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60799");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14494/");

  script_description(desc);
  script_summary("Check AV Arcade vulnerable version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Port
acPort = get_http_port(default:80);
if(!acPort){
  exit(0);
}

foreach dir (make_list("/avarcade", "/avarcade/upload/" , cgi_dirs()))
{
  ## Send and Recieve request
  sndReq = http_get(item:string(dir, "/index.php"), port:acPort);
  rcvRes = http_send_recv(port:acPort, data:sndReq);

  ## Confirm application is AV Arcade
  if(">AV Arcade" >< rcvRes && ">AV Scripts</" >< rcvRes)
  {
    ## Try to get the Admin page to grep the version
    sndReq = http_get(item:string(dir, "/admin/stats.php"), port:acPort);
    rcvRes = http_send_recv(port:acPort, data:sndReq);

    if(">AV Arcade" >< rcvRes)
    {
      acVer = eregmatch(pattern:"> ([0-9.]+)", string:rcvRes);
      if(acVer[1] != NULL)
      {
        ## Check the AV Arcade version
        if(version_is_equal(version:acVer[1], test_version:"3.0"))
        {
          security_hole(acPort);
          exit(0);
        }
      }
    }
  }
}

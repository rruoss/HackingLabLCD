##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_textpattern_cms_rfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Textpattern CMS 'index.php' Remote File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code on
  the vulnerable Web server.
  Impact Level: Application.";
tag_affected = "Textpattern CMS version 4.2.0";

tag_insight = "The flaw is due to an error in 'index.php', which is not properly
  sanitizing user-supplied data via 'inc' parameter. This allows an attacker to
  include arbitrary files.";
tag_solution = "No solution or patch is available as of 8th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://textpattern.com/download";
tag_summary = "This host is running Textpattern and is prone to remote file inclusion
  vulnerability.";

if(description)
{
  script_id(801442);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-11 07:48:04 +0100 (Thu, 11 Nov 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-3205");
  script_name("Textpattern CMS 'index.php' Remote File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61475");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14823/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1008-exploits/textpattern-rfi.txt");

  script_description(desc);
  script_summary("Check for the vesion of Textpattern CMS");
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

## Get HTTP port
cmsPort = get_http_port(default:80);
if(!cmsPort){
  exit(0);
}

foreach dir (make_list("/textpattern", "/", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir , "/index.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  ## Confirm application is Textpattern CMS
  if(">Textpattern<" >< rcvRes || "Textpattern CMS" >< rcvRes)
  {
    sndReq = http_get(item:string(dir, "/README.txt"), port:cmsPort);
    rcvRes = http_send_recv(port:cmsPort, data:sndReq);

    ## Grep the version
    cmsVer = eregmatch(pattern:"Textpattern ([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      ## Check the Textpattern version equal to 4.2.0
      if(version_is_equal(version:cmsVer[1], test_version:"4.2.0"))
      {
        security_hole(cmsPort);
        exit(0);
      }
    }
  }
}

##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_diy_cms_mult_rfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# DiY-CMS  Multiple Remote File Inclusion Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code on
  the vulnerable Web server.
  Impact Level: Application.";
tag_affected = "DiY-CMS version 1.0";

tag_insight = "Multiple flaws are due to:
  - An error in 'modules/guestbook/blocks/control.block.php', which is not
    properly validating the input passed to the 'lang' parameter.
  - An error in the 'index.php', which is not properly validating the input
    passed to 'main_module' parameter.
  - An error in the 'includes/general.functions.php', which is not properly
    validating the input passed to 'getFile' parameter.";
tag_solution = "No solution or patch is available as of 8th September, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://webscripts.softpedia.com/scriptDownload/DiY-CMS-Download-63258.html";
tag_summary = "This host is running DiY-CMS and is prone to multiple remote file
  inclusion vulnerabilities.";

if(description)
{
  script_id(801512);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-3206");
  script_name("DiY-CMS  Multiple Remote File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61454");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14822/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1008-exploits/diycms-rfi.txt");

  script_description(desc);
  script_summary("Check for the vesion of DiY-CMS");
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

foreach dir (make_list("/diycms/diy", "/", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir , "/index.php"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  ## Confirm application is DiY-CMS
  if("<title>Welcome - Do It Yourself CMS - Using DiY-CMS<" >< rcvRes)
  {
    ## Grep the version
    cmsVer = eregmatch(pattern:"DiY-CMS ([0-9.]+)", string:rcvRes);
    if(cmsVer[1] != NULL)
    {
      ## Check the Textpattern version equal to 1.0
      if(version_is_equal(version:cmsVer[1], test_version:"1.0"))
      {
        security_hole(cmsPort);
        exit(0);
      }
    }
  }
}

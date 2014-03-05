##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_irokez_cms_sql_inj_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Irokez CMS 'id' Parameter SQL Injection Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to access or modify data,
  or exploit latent vulnerabilities in the underlying database.
  Impact Level: Application.";
tag_affected = "Irokez CMS version 0.7.1 and prior";

tag_insight = "The flaw is caused by an input validation error in the 'select()' function
  when processing the 'id' parameter, which could be exploited by malicious
  people to conduct SQL injection attacks.";
tag_solution = "No solution or patch is available as of 07th September, 2010. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.irokez.org/download/cms/";
tag_summary = "This host is running Irokez CMS and is prone SQL injection
  vulnerability.";

if(description)
{
  script_id(801445);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
  script_cve_id("CVE-2009-4982");
  script_bugtraq_id(35957);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Irokez CMS 'id' Parameter SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/23497");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2167");

  script_description(desc);
  script_summary("Check Irokez CMS is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
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

## Get HTTP Port
cmsPort = get_http_port(default:80);
if(!cmsPort){
  exit(0);
}

foreach dir (make_list("/irokez", "/cms", "/", cgi_dirs()))
{
  ## Send and Recieve request
  sndReq = http_get(item:string(dir, "/ru/"), port:cmsPort);
  rcvRes = http_send_recv(port:cmsPort, data:sndReq);

  ## Confirm application is Irokez CMS
  if("<title>Irokez" >< rcvRes)
  {
    ## Try exploit and check response to confirm vulnerability
    sndReq = http_get(item:string(dir, "/ru/news/7'"), port:cmsPort);
    rcvRes = http_send_recv(port:cmsPort, data:sndReq);
    if("You have an error" >< rcvRes && "syntax" >< rcvRes)
    {
      security_hole(cmsPort);
      exit(0);
    }
  }
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpx_sql_inj_vuln_nov08.nasl 16 2013-10-27 13:09:52Z jan $
#
# PHPX news_id SQL Injection Vulnerability - Nov08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful attack could lead to execution of arbitrary sql commands.
  Impact Level: Application

  NOTE: Vulnerability exists only when magic_quotes_gpc is disabled.";

tag_affected = "PHPX Version 3.5.16 and prior on all running platform.";
tag_insight = "The flaw is due to sql commands with uppercase characters passed
  with the news_id parameter to includes/news.inc.php which is not properly
  sanitised before being used.";
tag_solution = "No solution or patch is available as of 13th November, 2008. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://phpx.thisrand.com/project.php";
tag_summary = "The host is running PHPX, which is prone to SQL Injection
  Vulnerability.";

if(description)
{
  script_id(800134);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5000");
  script_bugtraq_id(23033);
  script_name("PHPX news_id SQL Injection Vulnerability - Nov08");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32564");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6996");

  script_description(desc);
  script_summary("Check for the Version of PHPX");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

dirs = make_list("/phpx", cgi_dirs());
foreach dir (dirs)
{
  sndReq = http_get(item:string(dir + "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if(rcvRes =~ "Powered by.+PHPX")
  {
    phpxVer = eregmatch(pattern:"PHPX ([0-9.]+)", string:rcvRes);
    if(phpxVer != NULL)
    {
      # Check for PXPX Version <= 3.5.16
      if(version_is_less_equal(version:phpxVer[1], test_version:"3.5.16")){
        security_hole(0);
      }
    }
    exit(0);
  }
}

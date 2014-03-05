###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clanlite_sql_inj_n_xss_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# ClanLite SQL Injection and Cross-Site Scripting Vulnerabilities
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
tag_impact = "Successful attack could lead to execution of arbitrary scripting code or
  SQL commands in the context of an affected application, which allows an
  attacker to steal cookie-based authentication credentials or access and
  modify data.
  Impact Level: Application";
tag_affected = "ClanLite Version 2.2006.05.20 and prior.";
tag_insight = "The flaws are due to error in service/calendrier.php and
  service/profil.php whcih are not properly sanitized before being used.";
tag_solution = "No solution or patch is available as of 27th November, 2008. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.clanlite.org/";
tag_summary = "The host is running ClanLite, and is prone to SQL Injection and
  Cross-Site Scripting Vulnerabilities.";

if(description)
{
  script_id(800145);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5214", "CVE-2008-5215");
  script_bugtraq_id(29156);
  script_name("ClanLite SQL Injection and Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5595");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/42331");

  script_description(desc);
  script_summary("Check for the Version of ClanLite");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/clanlite", cgi_dirs()))
{
  sndReq = http_get(item:string(dir + "/service/index_pri.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("<title>ClanLite" >< rcvRes)
  {
    if(safe_checks())
    {
      clVer = eregmatch(pattern:"ClanLite<.+ V([0-9.]+)", string:rcvRes);
      if(clVer[1] != NULL)
      {
        # Check for ClanLite Version <= 2.2006.05.20
        if(version_is_less_equal(version:clVer[1], test_version:"2.2006.05.20")){
          security_hole(0);
        }
      }
      exit(0);
    }

    url = string(dir + "/service/calendrier.php?mois=6&annee='>" +
                       "<script>alert(document.cookie)</script>");
    sndReq = http_get(item:url, port:port);
    rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);
    if(rcvRes == NULL){
      exit(0);
    }

    if("<script>alert(document.cookie)</script>" >< rcvRes){
      security_hole(port);
    }
    exit(0);
  }
}

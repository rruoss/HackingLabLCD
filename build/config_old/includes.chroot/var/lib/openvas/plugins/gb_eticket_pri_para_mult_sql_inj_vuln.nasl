###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eticket_pri_para_mult_sql_inj_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# eTicket pri Parameter Multiple SQL Injection Vulnerabilities
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
tag_impact = "Successful attack could allow manipulation of the database by injecting
  arbitrary SQL queries.
  Impact Level: Application";
tag_affected = "eTicket Version 1.5.7 and prior.";
tag_insight = "Input passed to the pri parameter of index.php, open.php, open_raw.php, and
  newticket.php is not properly sanitised before being used in SQL queries.";
tag_solution = "Update to Version 1.7.0 or later.
  http://www.eticketsupport.com/";
tag_summary = "The host is running eTicket, which is prone to multiple SQL Injection
  vulnerabilities.";

if(description)
{
  script_id(800141);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-26 16:25:46 +0100 (Wed, 26 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5165");
  script_bugtraq_id(29973);
  script_name("eTicket pri Parameter Multiple SQL Injection Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30877");
  script_xref(name : "URL" , value : "http://www.eticketsupport.com/announcements/170_is_in_the_building-t91.0.html");
  script_xref(name : "URL" , value : "http://www.digitrustgroup.com/advisories/web-application-security-eticket2.html");

  script_description(desc);
  script_summary("Check for the Version of eTicket");
  script_category(ACT_GATHER_INFO);
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

foreach dir (make_list("/eTicket", cgi_dirs()))
{
  sndReq = http_get(item:string(dir + "/license.txt"), port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("eTicket" >< rcvRes)
  {
    eTicVer = eregmatch(pattern:"eTicket ([0-9.]+)", string:rcvRes);
    if(eTicVer[1] != NULL)
    {
      # Check for eTicket Version <= 1.5.7
      if(version_is_less_equal(version:eTicVer[1], test_version:"1.5.7")){
        security_hole(0);
      }
    }
    exit(0);
  }
}

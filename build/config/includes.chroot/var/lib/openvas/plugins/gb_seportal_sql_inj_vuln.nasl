###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seportal_sql_inj_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# SePortal poll.php SQL Injection Vulnerability
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
tag_impact = "Successful attack could lead to execution of arbitrary SQL queries.
  Impact Level: Application";
tag_affected = "SePortal Version 2.4 and prior on all running platform.";
tag_insight = "Input passed to the poll_id parameter in poll.php and to sp_id parameter
  in staticpages.php files are not properly sanitised before being used in
  an SQL query.";
tag_solution = "Upgrade to SePortal Version 2.5 or later
  For updates refer to http://www.seportal.org/";
tag_summary = "The host is running SePortal which is prone to SQL Injection
  Vulnerability.";

if(description)
{
  script_id(800143);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-11-27 14:04:10 +0100 (Thu, 27 Nov 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2008-5191");
  script_bugtraq_id(29996);
  script_name("SePortal poll.php SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30865");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5960");

  script_description(desc);
  script_summary("Check for the Version of SePortal");
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

foreach dir (make_list("/seportal", cgi_dirs()))
{
  sndReq = http_get(item:string(dir + "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port,data:sndReq,bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("SePortal" >< rcvRes)
  {
    sepVer = eregmatch(string:rcvRes, pattern:"SePortal<.+ ([0-9]\.[0-9.]+)");
    if(sepVer[1] != NULL)
    {
      # Check for SePortal Version <= 2.4
      if(version_is_less_equal(version:sepVer[1], test_version:"2.4")){
        security_hole(0);
      }
    }
    exit(0);
  }
}

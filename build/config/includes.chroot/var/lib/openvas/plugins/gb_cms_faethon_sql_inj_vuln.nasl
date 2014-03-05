###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cms_faethon_sql_inj_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# CMS Faethon 'info.php' SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "CMS Faethon version 2.2 Ultimate.";
tag_insight = "The flaw is due to input passed to the 'item' parameter in 'info.php'
  is not properly sanitised before being used in SQL queries.";
tag_solution = "No solution or patch is available as of 15th September, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/cmsfaethon/";
tag_summary = "The host is running CMS Faethon and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_id(802162);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-16 17:22:17 +0200 (Fri, 16 Sep 2011)");
  script_cve_id("CVE-2009-5094");
  script_bugtraq_id(33775);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("CMS Faethon 'info.php' SQL Injection Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30098");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48758");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/8054/");

  script_description(desc);
  script_summary("Determine if CMS Faethon is prone to SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir(make_list("/faethon", "/22_ultimate", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get (item: string (dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('>Powered by <' >< res && '>CMS Faethon' >< res)
  {
    ## Try SQL injection and check the response to confirm vulnerability
    url = dir + "/info.php?item='";
    if(http_vuln_check(port:port, url:url, pattern:'You have an error in' +
                                  ' your SQL syntax;'))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}

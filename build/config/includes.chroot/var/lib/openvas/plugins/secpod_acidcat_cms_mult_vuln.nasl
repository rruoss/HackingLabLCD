##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_acidcat_cms_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Acidcat CMS Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to restart the
  installation process and an attacker can download the database containing
  credentials via a direct request for databases/acidcat_3.mdb.
  Impact Level: Application.";
tag_affected = "Acidcat CMS 3.5.3 and prior";

tag_insight = "The flaws are due to,
  - 'install.asp' and other 'install_*.asp' scripts which can be accessed
    even after the installation finishes, which might allow remote attackers
    to restart the installation process.
  - improper access restrictions to the 'acidcat_3.mdb' database file in
    the databases directory. An attacker can download the database containing
    credentials via a direct request for databases/acidcat_3.mdb.";
tag_solution = "No solution or patch is available as of 23rd March 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.acidcat.com/";
tag_summary = "This host is running Acidcat CMS and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900750);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-23 15:59:14 +0100 (Tue, 23 Mar 2010)");
  script_cve_id("CVE-2010-0976", "CVE-2010-0984");
  script_name("Acidcat CMS Multiple Vulnerabilities");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
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
  script_xref(name : "URL" , value : "http://osvdb.org/61436");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38084");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55329");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55331");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10972");

  script_description(desc);
  script_summary("Check through the attack string on Acidcat CMS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
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

## Get HTTP port
acidPort = get_http_port(default:80);
if(!acidPort){
  exit(0);
}

## Check for the Acidcat CMS
foreach dir (make_list("/acidcat", "/Acidcat" ,"/", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/main_login.asp"), port:acidPort);
  rcvRes = http_send_recv(port:acidPort, data:sndReq);

  if(">Acidcat ASP CMS" >< rcvRes)
  {
    ## Send an exploit and recieve the response
    sndReq = http_get(item:string(dir, "/install.asp"), port:acidPort);
    rcvRes = http_send_recv(port:acidPort, data:sndReq);

    ## Check the response for installation guide
    if("Welcome to the Acidcat CMS installation guide" >< rcvRes)
    {
      security_hole(acidPort);
      exit(0);
    }
  }
}

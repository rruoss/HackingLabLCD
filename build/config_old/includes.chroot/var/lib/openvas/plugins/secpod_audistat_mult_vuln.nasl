###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_audistat_mult_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# AudiStat multiple vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow the attackers to inject arbitrary SQL
  code, execute arbitrary HTML and script code on the vulnerable system.
  Impact Level: Application";
tag_affected = "AudiStat version 1.3 and prior";
tag_insight = "Input passed to the 'year', 'month' and 'mday' parameters in index.php are
  not properly sanitised before being returned to the user or before being
  used in the sql queries.";
tag_solution = "No solution or patch is available as of 27rd March, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://adubus.free.fr/audistat/";
tag_summary = "The host is running AudiStat and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902029);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-1050", "CVE-2010-1051", "CVE-2010-1052");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("AudiStat multiple vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38494");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11334");

  script_description(desc);
  script_copyright("Copyright (c) 2010 SecPod");
  script_summary("Check through the attack string and version of AudiStat");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_audistat_detect.nasl");
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

# Check AudiStat is running
statPort = get_http_port(default:80);
if(!statPort){
  exit(0);
}

## Get version and installed path from KB
statVer = get_kb_item("www/" + statPort + "/Audistat");
if(isnull(statVer)){
 exit(0);
}

statVer = eregmatch(pattern:"^(.+) under (/.*)$", string:statVer);
if(!isnull(statVer[2]))
{
  ## Checking for the exploit on AudiStat
  sndReq = http_get(item:string(statVer[2], "/?year=kaMtiEz&month=tukulesto" +
                    "&mday=<script>alert('OpenVAS-XSS-Testing')</script>"),
                    port:statPort);
  rcvRes = http_send_recv(port:statPort, data:sndReq);
  if("OpenVAS-XSS-Testing" >< rcvRes)
  {
    security_hole(statPort);
    exit(0);
  }
}

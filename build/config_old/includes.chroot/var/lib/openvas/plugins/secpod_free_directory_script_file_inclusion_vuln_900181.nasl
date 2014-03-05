##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_free_directory_script_file_inclusion_vuln_900181.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Free Directory Script 'API_HOME_DIR' File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_affected = "Free Directory Script version 1.1.1 and prior.

  Workaround: Edit the source code to ensure that input is properly verified.";

tag_impact = "Successful exploitation will let the attacker add, modify or delete files 
  from the server and can let the attacker install trojans or backdoors.
  Impact Level: Application";
tag_summary = "This host is installed with Free Directory Script and is prone to
  File Inclusion Vulnerability.";

tag_insight = "The Error occurs when passing an input parameter into the 'API_HOME_DIR' in
  'init.php' file which is not properly verified before being used to include
  files. This can be exploited to include arbitrary files from local or
  external resources.";
tag_solution = "No patch is available as on 24th November, 2008.";

if(description)
{
  script_id(900181);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("Free Directory Script 'API_HOME_DIR' File Inclusion Vulnerability");
  script_summary("Check for the vulnerable version of Free Directory Script");
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

  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7155");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32745");

 script_description(desc);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
 exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach path (make_list("/FreeDirectory", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/index.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);
  if(rcvRes == NULL){
    exit(0);
  }

  if(egrep(pattern:"Free Directory Script", string:rcvRes) && 
     egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
  {
    pattern = "FDS Version (0(\..*)|1\.(0(\..*)?|1(\.[01])?))($|[^.0-9])";
    if(egrep(pattern:pattern, string:rcvRes)){
      security_warning(port);
      exit(0);
    }
  }
}

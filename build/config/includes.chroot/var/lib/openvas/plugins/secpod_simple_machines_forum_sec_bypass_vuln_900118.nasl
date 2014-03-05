##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_simple_machines_forum_sec_bypass_vuln_900118.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Simple Machines Forum Password Reset Vulnerability
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
tag_impact = "Attackers can guess the validation code and reset the user
        password to the one of their choice.

 Impact Level : Application";

tag_solution = "Update to version 1.1.6
 http://download.simplemachines.org/


        CVSS  Temporal Score : 5.0";

tag_affected = "Simple Machines Forum versions prior to 1.1.6 on";

tag_insight = "The vulnerability exists due to the application generating weak
        validation codes for the password reset functionality which allows
        for easy validation code guessing attack.";

tag_summary = "The host has Simple Machines Forum, which is prone to security
 bypass vulnerability.";


if(description)
{
 script_id(900118);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
 script_cve_id("CVE-2008-6971");
 script_bugtraq_id(31053);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_name("Simple Machines Forum Password Reset Vulnerability");
 script_summary("Check for the vulnerable version of Simple Machines");
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
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6392");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31750/");
 script_xref(name : "URL" , value : "http://www.simplemachines.org/community/index.php?topic=260145.0");
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!port){
        exit(0);
 }

 foreach path (make_list("/sm_forum", cgi_dirs()))
 {
        sndReq = http_get(item:string(path, "/index.php"), port:port);
        rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
        if(rcvRes == NULL){
                exit(0);
        }

	if(egrep(pattern:"sm_forum", string:rcvRes) &&
           egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
	{
		if(egrep(pattern:"SMF (1\.0(\..*)?|1\.1(\.[0-5])?)[^.0-9]",
			 string:rcvRes)){
			security_hole(port);
		} 
		exit(0);
       }
 }

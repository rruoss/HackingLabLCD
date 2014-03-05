##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dotproject_mult_xss_n_sql_inj_vuln_900116.nasl 16 2013-10-27 13:09:52Z jan $
# Description: dotProject Multiple XSS and SQL Injection Vulnerabilities
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
tag_impact = "Successful exploitation will allow attackers to steal cookie
        based authentication credentials of user and administrator, and can
        also execute arbitrary code in the browser of an unsuspecting user
        in the context of an affected site.

 Impact Level : Application";

tag_solution = "Upgrade to dotProject version 2.1.3 or later
 For updates check, http://www.dotproject.net/";

tag_insight = "The flaws exists due to, 
        - improper sanitisation of input value passed to inactive, date,
          calendar, callback and day_view, public, dialog and ticketsmith
          parameters in index.php before being returned to the user.
        - failing to validate the input passed to the tab and user_id parameter
	  in index.php file, before being used in SQL queries.";

tag_summary = "The host is running dotProject, which is prone to multiple Cross
 Site Scripting and SQL injection vulnerabilities.";

tag_affected = "dotProject version 2.1.2 and prior on all platform.";

if(description)
{
 script_id(900116);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-02 16:25:07 +0200 (Tue, 02 Sep 2008)");
 script_cve_id("CVE-2008-3886");
 script_bugtraq_id(30924);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_name("dotProject Multiple XSS and SQL Injection Vulnerabilities");
 script_summary("Check for the vulnerable version of dotProject");
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
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31681/");
 script_xref(name : "URL" , value : "http://packetstorm.linuxsecurity.com/0808-exploits/dotproject-sqlxss.txt");
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!port){
        exit(0);
 }

 foreach path (make_list("/xampp/dotproject_2_1_2/dotproject", cgi_dirs()))
 {
        sndReq = http_get(item:string(path, "/index.php"), port:port);
        rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
        if(rcvRes == NULL){
                exit(0);
        }

	if(egrep(pattern:"dotProject", string:rcvRes) &&
           egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
	{
		if(safe_checks())
		{
			if(egrep(pattern:"Version ([01]\..*|2\.(0(\..*)?|" +
					 "1(\.[0-2])?))[^.0-9]", string:rcvRes)){
				security_warning(port);
			}
			exit(0);
		}

                sndReq = http_get(item:string(path, "/index.php?m=public&a=" +
				  "calendar&dialog=1&callback=setCalendar%22" +
				  "%3E%3Cimg/src/onerror=alert(101010)%3E"),
				  port:port);
                rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
                if(rcvRes == NULL){
                        exit(0);
                }

                if('alert(101010)%3E' >< rcvRes){
                        security_warning(port);
                }
                exit(0);
       }
 }

##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xampp_mult_xss_vuln_900023.nasl 16 2013-10-27 13:09:52Z jan $
# Description: XAMPP for Linux text Parameter Multiple XSS Vulnerabilities
#
# Authors:
# Chandan S <schandan@secpod.com>
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
tag_affected = "Xampp Linux 1.6.7 and prior on Linux (All).";

tag_solution = "Upgrade to Xampp Linux version 1.7.3 or later,
 For updates check, http://www.apachefriends.org/en/xampp-linux.html";

tag_impact = "Successful exploitation could allow remote attackers to execute
        arbitrary HTML and script code.
 Impact Level : Application";

tag_insight = "The flaw is due the input passed to the parameter text in iart.php and
        ming.php files are not santised before being returned to the user.";


tag_summary = "The host is running Xampp, which is prone to multiple cross site
 scripting vulnerabilities.";


if(description)
{
 script_id(900023);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-07 17:25:49 +0200 (Thu, 07 Aug 2008)");
 script_cve_id("CVE-2008-3569");
 script_bugtraq_id(30535);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_name("XAMPP for Linux text Parameter Multiple XSS Vulnerabilities");
 script_summary("Check for the vulnerable version of XAMPP");
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
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "impact" , value : tag_impact);
   script_tag(name : "affected" , value : tag_affected);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/495096");
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!port){
        exit(0);
 }

 foreach path (make_list("/xampp", cgi_dirs()))
 {
        sndReq = http_get(item:string(path, "/start.php"), port:port);
        rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
        if(rcvRes == NULL){
                exit(0);
        }

	if(egrep(pattern:"XAMPP for Linux", string:rcvRes) &&
           egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
	{
		if(safe_checks())
		{
			if(egrep(pattern:"XAMPP for Linux 1\.([0-5]\..*|6\.[0-7])" +
					 "($|[^.0-9])", string:rcvRes)){
				security_warning(port);
			}
			exit(0);
		}

		# XSS request sent to parameter text in iart.php
                sndReq = http_get(item:string(path, "/iart.php?text=%22%3E%" +
			 "3E%3C%3C%3E%3E%22%22%3Cscript%3Ealert(document.alert)" +
			 "%3C/script%3E"), port:port);
                rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
                if(rcvRes == NULL){
                        exit(0);
                }

                if('<script>alert(document.alert)</script>' >< rcvRes){
                        security_warning(port);
                }
                exit(0);
        }
 }

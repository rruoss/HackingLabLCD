##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_mult_vuln_900219.nasl 16 2013-10-27 13:09:52Z jan $
# Description: WordPress Multiple Vulnerabilities - Sept08
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to reset the
        password of arbitrary accounts, guess randomly generated passwords,
        obtain sensitive information and possibly to impersonate users and
        tamper with network data.
 Impact Level : Application";

tag_solution = "Upgrade to WordPress 2.6.2 or later.
 http://wordpress.org/";

tag_affected = "WordPress 2.6.1 and prior versions.";

tag_insight = "The flaws are due to,
                - SQL column-truncation issue.
		- Weakness in the entropy of generated passwords.
		- functions get_edit_post_link(), and get_edit_comment_link() fail
                  to use SSL when transmitting data.";


tag_summary = "This host is running WordPress, which is prone to multiple
 vulnerabilities.";


if(description)
{
 script_id(900219);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
 script_bugtraq_id(30750, 31068, 31115);
 script_cve_id("CVE-2008-3747");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_name("WordPress Multiple Vulnerabilities");
 script_summary("Check for version of WordPress");
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
 script_xref(name : "URL" , value : "http://www.sektioneins.de/advisories/SE-2008-05.txt");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2008/Sep/0194.html");
 script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln31068.html");
 script_xref(name : "URL" , value : "http://www.juniper.net/security/auto/vulnerabilities/vuln30750.html");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!port){
        exit(0);
 }

 foreach path (make_list("/wordpress", cgi_dirs()))
 {
        sndReq = http_get(item:string(path, "/index.php"), port:port);
        rcvRes = http_keepalive_send_recv(port:port, data:sndReq);
        if(rcvRes == NULL){
                exit(0);
        }

	if(egrep(pattern:"Powered by WordPress", string:rcvRes) &&
           egrep(pattern:"^HTTP/.* 200 OK", string:rcvRes))
        {
                if(egrep(pattern:"WordPress 2\.([0-5](\..*)?|6(\.[01])?)[^.0-9]",
                         string:rcvRes)){
                        security_hole(port);
                }
                exit(0);
        }
 }

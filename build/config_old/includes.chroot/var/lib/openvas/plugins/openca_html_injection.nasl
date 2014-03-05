###################################################################
# OpenVAS Network Vulnerability Test
#
# OpenCA HTML injection
#
# LSS-NVT-2009-007
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
tag_summary = "OpenCA is vulnerable to a HTML injection attack due to inadequate 
validation / filtering of user input into a web form frontend. 

Versions up to 0.9.2 RC6 are vulnerable.

Detailed info: http://www.securityfocus.com/bid/11113";

tag_solution = "Upgrade OpenCA to the newer version.";

if (description) {

    script_id(102007);
    script_version("$Revision: 43 $");
    script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
    script_tag(name:"creation_date", value:"2009-07-28 17:03:43 +0200 (Tue, 28 Jul 2009)");
    script_tag(name:"cvss_base", value:"4.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
    script_tag(name:"risk_factor", value:"Medium");

    script_cve_id("CVE-2004-0787");
    script_bugtraq_id(11113);

    script_name("OpenCA HTML injection");

    desc = "
    Summary:
    " + tag_summary + "
    Solution:
    " + tag_solution;    script_description(desc);

    script_summary("Checks if OpenCA is vulnerable to the HTML injection vulnerability");

    script_category(ACT_GATHER_INFO);
    script_family("Web application abuses");

    script_copyright("Copyright (C) 2009 LSS");
    script_require_ports("Services/www", 80);

    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
      script_tag(name : "solution" , value : tag_solution);
      script_tag(name : "summary" , value : tag_summary);
    }
    exit(0);
}

include("http_func.inc");
include("version_func.inc");

RESOURCE[0] = "/cgi-bin/pub/pki?cmd=serverInfo";
RESOURCE[1] = "/cgi-bin/pki/pub/pki?cmd=serverInfo";

function get_OpenCA_version(resource) {
    req = http_get(port:port, item:resource);
    res = http_send_recv(port:port, data:req);

    if (res == NULL)
        return NULL;

    regex = 'OpenCA Server Version ((([[:digit:]]\\.?)+)[[:space:]]*(-?[Rr][Cc]([[:digit:]]+))?)';
    match = eregmatch(pattern:regex, string:res);

    result = NULL;
    if (match != NULL) {
        result[0] = match[1]; # full version number
        result[1] = match[2]; # version without -rc
        result[2] = match[5]; # RC number only
    }

    return result;
}

# checks for OpenCA version under 0.9.2 RC6

function is_vulnerable(version, rc) {
    if (version_is_less(version:version, test_version:'0.9.2'))
        return 1;

    if (rc != NULL && 
            version_is_equal(version:version, test_version:'0.9.2') &&
            rc <= 6)
        return 1;

    return 0;
}

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

foreach resource (RESOURCE) {
    version = get_OpenCA_version(resource:resource);
    if (version == NULL)
        continue;

    kb = 'www/' + port + '/openca/version';
    set_kb_item(name:kb, value:version[0]);

    if (is_vulnerable(version:version[1], rc:version[2])) 
        security_warning(port);

    break;
}

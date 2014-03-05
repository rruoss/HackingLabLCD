###############################################################################
# OpenVAS Vulnerability Test
# $Id:
#
# Centralized and organized host informations base
#
# Authors:
# Henri Doreau <henri.doreau@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

##
# This script exports a function to store host information in a structured
# way.
#
# <host>
#   <detail>
#     <name>OS</name>
#     <value>Debian</value>
#     <method>
#       <nvt>1.2.3.4.5.6</nvt>
#       <description>NVT description</description>
#     </method>
#   </detail>
#   <detail>
#     <name>OS</name>
#     <value>cpe:/o:debian_linux:debian:5.0</value>
#     <method>
#       <nvt>1.2.3.4</nvt>
#       <description>another NVT description</description>
#     </method>
#   </detail>
# </host>
#
#
#
# For this example, we would use these KB entries:
# ------------------------------------------------
#
# HostDetails                     => "OS"
# HostDetails/NVT                 => "1.2.3.4.5.6", "1.2.3.4"
# --
# HostDetails/NVT/1.2.3.4.5.6     => "NVT Description"
# HostDetails/NVT/1.2.3.4.5.6/OS  => "Debian"
# --
# HostDetails/NVT/1.2.3.4         => "another NVT description"
# HostDetails/NVT/1.2.3.4/OS      => "cpe:/o:debian_linux:debian:5.0"
##

include("xml.inc");


# Best OS detection sources, sorted by decreasing accuracy (best is first).
OS_CPE_SRC = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103633", # gb_ros_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103799", # gb_cisco_nx_os_detect.nasl
    "1.3.6.1.4.1.25623.1.0.96207",  # gb_windows_cpe_detect.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.103621", # gb_smb_windows_detect.nasl
    "1.3.6.1.4.1.25623.1.0.104000", # nmap_net.nasl
    "1.3.6.1.4.1.25623.1.0.10267",  # ssh_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.102002"  # os_fingerprint.nasl
);

OS_TXT_SRC = make_list(
    "1.3.6.1.4.1.25623.1.0.103220", # gb_greenbone_os_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103633", # gb_ros_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103628", # gb_apple_mobile_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103418", # gb_vmware_esx_web_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103417", # gb_vmware_esx_snmp_detect.nasl
    "1.3.6.1.4.1.25623.1.0.103799", # gb_cisco_nx_os_detect.nasl
    "1.3.6.1.4.1.25623.1.0.50282",  # gather-package-list.nasl
    "1.3.6.1.4.1.25623.1.0.101013", # remote-detect-MDNS.nasl
    "1.3.6.1.4.1.25623.1.0.104000", # nmap_net.nasl
    "1.3.6.1.4.1.25623.1.0.14259",  # nmap.nasl
    "1.3.6.1.4.1.25623.1.0.102011", # smb_nativelanman.nasl
    "1.3.6.1.4.1.25623.1.0.103429", # gb_snmp_os_detection.nasl
    "1.3.6.1.4.1.25623.1.0.102002", # os_fingerprint.nasl
    "1.3.6.1.4.1.25623.1.0.10884"   # ntp_open.nasl
);


function register_host_detail(name, value, nvt, desc) {
  local_var tokens;

  if(name != "port") {
      set_kb_item(name:"HostDetails", value:name);
      set_kb_item(name:"HostDetails/NVT", value:nvt);
      if (!isnull(desc))
        replace_kb_item(name:"HostDetails/NVT/" + nvt, value:desc);
  }

  if(value)
    set_kb_item(name:"HostDetails/NVT/" + nvt + "/" + name, value:value);

  # gather-package-list.nasl sets precise OS CPE keys that we use to
  # efficiently schedule LSCs.
  if (name == "OS" && "cpe:/o:" >< value && nvt == "1.3.6.1.4.1.25623.1.0.50282") {
    tokens = split(value, sep:":", keep:0);

    if (tokens && tokens[0] && tokens[1] && tokens[2] && tokens[3])
      set_kb_item(name:string("HostDetails/OS/", tokens[0], ":", tokens[1], ":",
                              tokens[2], ":", tokens[3]),
                  value:TRUE);
  }
}

function register_product(cpe, location, port, nvt) {
  local_var port;

  register_host_detail(name:"App", value:cpe, nvt:nvt);
  register_host_detail(name:cpe, value:location, nvt:nvt);
  if(port) {
    register_host_detail(name:"port", value:port, nvt:nvt);
  }
}

# provided for conveniency: host_details_list("OS")
function host_details_list(key) {
  return get_kb_list("HostDetails/NVT/*/" + key);
}

function report_host_detail_single(name, value, nvt, desc) {
  local_var report;

  report = '';

  report += xml_open_tag(tag:'host');
  report += xml_open_tag(tag:'detail');
  report += xml_tagline(tag:'name', value:name);
  report += xml_tagline(tag:'value', value:value);
  report += xml_open_tag(tag:'source');
  report += xml_tagline(tag:'type', value:"nvt");
  report += xml_tagline(tag:'name', value:nvt);

  if (!isnull(desc))
    report += xml_tagline(tag:'description', value:desc);
  else
    report += '<description/>';

  report += xml_close_tag(tag:'source');
  report += xml_close_tag(tag:'detail');
  report += xml_close_tag(tag:'host');

  log_message(proto:"Host_Details", data:report);
}

# Iterate over the host details and report them individually. Additionally
# report best CPE and TXT available concerning the remote OS.
function report_host_details() {
  local_var names, name, nvts, nvt, desc, details, item;


  # get the names of the host details we gathered
  names = get_kb_list("HostDetails");

  # list of concerned NVTs
  nvts = get_kb_list("HostDetails/NVT");
  foreach nvt (nvts) {
    # description of the current NVT
    desc = get_kb_item("HostDetails/NVT/" + nvt);

    # iterate over the registered entries...
    foreach name (names) {
      details = get_kb_list("HostDetails/NVT/" + nvt + "/" + name);

      # add a section in case the current NVT has some value for this entry
      foreach item (details) {
        if (!isnull(item)) {
          report_host_detail_single(name:name, value:item, nvt:nvt, desc:desc);
        }
      }
    }
  }

  # Report best OS entries
  report_best_os_cpe();
  report_best_os_txt();
}

function host_runs() {
  local_var ospattern, infolist;

  ospattern = _FCT_ANON_ARGS[0];

  infolist = host_details_list(key:"OS");
  if (isnull(infolist))
    return "unknown";

  foreach item (infolist)
    if (eregmatch(pattern:ospattern, string:item, icase:TRUE))
      return "yes";

  return "no";
}

function best_os_cpe() {
  local_var oid, res, entry;

  foreach oid (OS_CPE_SRC) {
    res = get_kb_list("HostDetails/NVT/" + oid + "/OS");
    if (!isnull(res)) {
      res = make_list(res);
      foreach entry (res) {
        # both CPE and free-form entries can be registered under the "OS" banner
        if ("cpe:/" >< entry)
          return entry;
      }
    }
  }
  return NULL;
}

function best_os_txt() {
  local_var oid, res, entry;

  foreach oid (OS_TXT_SRC) {
    res = get_kb_list("HostDetails/NVT/" + oid + "/OS");
    if (!isnull(res)) {
      res = make_list(res);
      foreach entry (res) {
        # both CPE and free-form entries can be registered under the "OS" banner
        if ("cpe:/" >!< entry)
          return entry;
      }
    }
  }
  return NULL;
}

function report_best_os_cpe() {
  local_var oid, res, best_os, desc;

  foreach oid (OS_CPE_SRC) {
    res = get_kb_list("HostDetails/NVT/" + oid + "/OS");

    if (!isnull(res)) {
      res = make_list(res);

      foreach best_os (res) {

        # discard non CPE entries
        if ("cpe:/" >!< best_os)
          continue;

        desc = get_kb_item("HostDetails/NVT/" + oid);
        report_host_detail_single(name:"best_os_cpe", value:best_os, nvt:oid, desc:desc);
        return; # There's only one "best" OS CPE. :)
      }
    }
  }
}

function report_best_os_txt() {
  local_var oid, res, best_os, desc;

  foreach oid (OS_TXT_SRC) {
    res = get_kb_list("HostDetails/NVT/" + oid + "/OS");

    if (!isnull(res)) {
      res = make_list(res);

      foreach best_os (res) {

        # discard CPE entries
        if ("cpe:/" >< best_os)
          continue;

        # in case we have several entries from this script...
        if (os_conflict(res, best_os))
          best_os = best_os + ' [possible conflict]';

        desc = get_kb_item("HostDetails/NVT/" + oid);
        report_host_detail_single(name:"best_os_txt", value:best_os, nvt:oid, desc:desc);
        return;
      }
    }
  }
}

function host_details_cpes() {
  local_var res, name, categories, details_list, item;

  res = make_list();

  # get all the registered entries for applications
  details_list = host_details_list(key:"App");

  if (!isnull(details_list))
    foreach item (details_list)
      if ("cpe:/" >< item)
        res = make_list(res, item);

  # get the best CPE we have for operating system (if any)
  item = best_os_cpe();
  if (!isnull(item))
    res = make_list(res, item);

  return res;
}

function os_conflict() {
  local_var oslist, bestos, is_cpe, item;

  oslist = _FCT_ANON_ARGS[0];
  bestos = _FCT_ANON_ARGS[1];

  is_cpe = FALSE;

  if ("cpe:/" >< bestos)
    is_cpe = TRUE;

  foreach item (oslist) {
    if (item == bestos)
      continue;

    # return true if the list contains at least one element of the same type (cpe or text)
    if (("cpe:/" >< item) == is_cpe)
      return TRUE;
  }
  return FALSE;
}

function get_app(cpe, nvt,loc) {
  local_var host_details, host_detail, res, port, loc;

   host_details = get_kb_list("HostDetails/NVT/*");

   if(!host_details) return NULL;

   foreach host_detail (keys(host_details)) {

     if(cpe >< host_detail) {

       host_values = split(host_detail, sep:"/", keep:FALSE);

       if(isnull(host_values[2]) || isnull(host_values[4]) || "cpe:" >!< host_values[3]) return NULL;

       res = make_array();

       res["OID"] = host_values[2];
       res["CPE"] = 'cpe:/' +  host_values[4];

       port = get_kb_item("HostDetails/NVT/" + res["OID"] + "/port");  # this could fork

       if(port) {
         res["port"] = port;
       }

       if(loc) {
         location = get_kb_item("HostDetails/NVT/" + res["OID"] + "/" + res["CPE"]); # this could fork
         res["LOCATION"] = location;
       }  

       # Store link between scripts.
       register_host_detail(name:"detected_by", value:res["OID"], nvt:nvt);
       register_host_detail(name:"detected_at", value:location, nvt:nvt);

       return res;

    }
  }

   return NULL;
}

function get_app_version(cpe, nvt, port) {
   local_var app, tokens, port;

   app = get_app(cpe:cpe, nvt:nvt);

   if (isnull(app))
     return NULL;

   if(port) {
     if(!app["port"] || app["port"] != port) {
       return FALSE;
     }
   }

   tokens = split(app["CPE"], sep:":", keep:0);

   if (!isnull(tokens[4])) {

     if (!isnull(tokens[5])) { # for example cpe:/a:extplorer:extplorer:2.1.0:RC5
       return tokens[4] + tokens[5];
     }

     return tokens[4];

   }

   return NULL;
}

function get_app_location(cpe, nvt, port) {
    local_var app, lport, port;

    app = get_app(cpe:cpe, nvt:nvt,loc:TRUE);

    if (isnull(app["LOCATION"]))
        return NULL;

    if(port) {
      if(!app["port"] || app["port"] != port) {
        return NULL;
      }
    }

    lport = eregmatch(string:app['LOCATION'], pattern:"([0-9]+)/[^0-9]+");

    if (!isnull(lport))
        return  int(lport[1]);
    else
        return app["LOCATION"];

}

function get_app_port(cpe, nvt) {
  local_var app, lport;

  app = get_app(cpe:cpe, nvt:nvt);

  if(isnull(app["LOCATION"]) && isnull(app["port"])) {
      return NULL;
  }

  if(app["port"]) {
      return app["port"];
  }

  return NULL;

}

function build_detection_report(app, version, install, regpath, cpe, concluded, extra) {

  local_var app, version, install, cpe, concluded, regpath;

  if(!version) version = 'unknown';

  report = 'Detected ' + app + ' version: ' + version +
           '\nLocation: ' + install;

  if(strlen(regpath) > 0) {
    report += '\nRegistry path: '+ regpath;
  }  

  if(strlen(cpe) > 0) {
    report += '\nCPE: '+ cpe;
  }

  if(strlen(concluded) > 0) {
    report += '\n\nConcluded from version identification result:\n' + concluded + '\n';
  }

  if(strlen(extra) > 0) {
    report += '\n' + extra + '\n';
  }

  return report;

}


# ClamTk, copyright (C) 2004-2012 Dave M
#
# This file is part of ClamTk (http://clamtk.sourceforge.net).
#
# ClamTk is free software; you can redistribute it and/or modify it
# under the terms of either:
#
# a) the GNU General Public License as published by the Free Software
# Foundation; either version 1, or (at your option) any later version, or
#
# b) the "Artistic License".
package ClamTk::Schedule;

# I haven't found a cross-distro Perl module for
# scheduling, so we have call crontab as a system command.

# use strict;
# use warnings FATAL => 'all';
$| = 1;

use POSIX 'locale_h';
use Locale::gettext;

use Glib 'TRUE', 'FALSE';

use open ':encoding(utf8)';

# This should be under /usr/bin, but we'll check anyway.
my $cmd =
      ( -e '/usr/bin/crontab' )       ? '/usr/bin/crontab'
    : ( -e '/usr/local/bin/crontab' ) ? '/usr/local/bin/crontab'
    : ( -e '/bin/crontab' )           ? '/bin/crontab'
    :                                   '';
chomp($cmd);

my ( $hour_s, $min_s, $hour_s_2, $min_s_2 );
my ( $root_b, $home_b );
my ( $scan_apply_btn, $scan_remove_btn );
my ( $defs_apply_btn, $defs_remove_btn );
my ( $scan_status,    $defs_status );
my $ignore_white;    # checked = scan whitelisted, unchecked = use

sub schedule_dialog {
    # These are the main $window's x/y coordinates.
    # Seems to work intermittently, and possibly
    # less expensive than sending $window itself.
    # The ->move below shifts it to those coordinates.
    my ( undef, $x, $y ) = @_;
    my $dialog =
        Gtk2::Dialog->new( gettext('Schedule'), undef,
        'destroy-with-parent' );
    $dialog->signal_connect( close   => sub { $dialog->destroy } );
    $dialog->signal_connect( destroy => sub { Gtk2->main_quit } );
    $dialog->move( $x, $y );

    my $tt = Gtk2::Tooltips->new();

    my $vbox = Gtk2::VBox->new;
    $dialog->get_content_area()->add($vbox);

    my $scan_f = Gtk2::Frame->new( gettext('Scan options') );
    $vbox->pack_start( $scan_f, FALSE, FALSE, 5 );
    $scan_f->set_border_width(3);
    #$scan_f->set_shadow_type('none');

    my $scan_b = Gtk2::VBox->new;
    $scan_f->add($scan_b);

    my $label1 = Gtk2::Label->new;
    $scan_b->pack_start( $label1, FALSE, FALSE, 0 );
    $label1->set_text( gettext('Scan my ... ') );

    my $dir_bb = Gtk2::HButtonBox->new;
    $scan_b->pack_start( $dir_bb, FALSE, FALSE, 0 );
    $dir_bb->set_layout('spread');

    $home_b = Gtk2::RadioButton->new( undef, gettext('Home (recommended)') );
    $home_b->can_focus(FALSE);
    $dir_bb->add($home_b);
    $tt->set_tip(
        $home_b,
        gettext(
            'This option will scan your home directory. This is the recommended option.'
            ) );
    $root_b = Gtk2::RadioButton->new( $home_b, gettext('entire computer') );
    $dir_bb->add($root_b);
    $tt->set_tip(
        $root_b,
        gettext(
            'This option will scan your entire computer but will exclude the /proc, /sys and /dev directories.'
            ) );

    my $label2 = Gtk2::Label->new;
    $scan_b->pack_start( $label2, FALSE, FALSE, 0 );
    $label2->set_text( gettext('at this time ... ') );

    my $time_hbox = Gtk2::HBox->new;
    $scan_b->pack_start( $time_hbox, FALSE, FALSE, 0 );

    $hour_s = Gtk2::SpinButton->new_with_range( 0, 23, 1 );
    $time_hbox->pack_start( $hour_s, TRUE, TRUE, 5 );
    $hour_s->set_wrap(TRUE);
    $tt->set_tip( $hour_s, gettext('Set the hour using a 24 hour clock.') );
    my $hour_l = Gtk2::Label->new( gettext('Hour') );
    $hour_l->set_alignment( 0.0, 0.5 );
    $time_hbox->pack_start( $hour_l, FALSE, TRUE, 5 );

    $min_s = Gtk2::SpinButton->new_with_range( 0, 59, 1 );
    $min_s->set_wrap(TRUE);
    $time_hbox->pack_start( $min_s, TRUE, TRUE, 5 );
    my $min_l = Gtk2::Label->new( gettext('Minute') );
    $min_l->set_alignment( 0.0, 0.5 );
    $time_hbox->pack_start( $min_l, FALSE, TRUE, 5 );

    $ignore_white =
        Gtk2::CheckButton->new( gettext('Scan my whitelisted directories') );
    $scan_b->pack_start( $ignore_white, FALSE, FALSE, 0 );
    $ignore_white->set_active(FALSE);

    my $time_bar = Gtk2::Toolbar->new;
    $scan_b->pack_start( $time_bar, FALSE, FALSE, 0 );
    $time_bar->set_style('icons');

    my $dsep = Gtk2::SeparatorToolItem->new;
    $dsep->set_draw(FALSE);
    $dsep->set_expand(TRUE);
    $time_bar->insert( $dsep, -1 );

    $scan_apply_btn = Gtk2::ToolButton->new_from_stock('gtk-add');
    $time_bar->insert( $scan_apply_btn, -1 );
    $scan_apply_btn->signal_connect( 'clicked' => \&apply_scan );

    $time_bar->insert( Gtk2::SeparatorToolItem->new, -1 );

    $scan_remove_btn = Gtk2::ToolButton->new_from_stock('gtk-remove');
    $time_bar->insert( $scan_remove_btn, -1 );
    $scan_remove_btn->signal_connect(
        'clicked' => sub { remove('clamtk-scan') } );

    my $defs_f = Gtk2::Frame->new( gettext('Antivirus signature options') );
    $vbox->pack_start( $defs_f, FALSE, FALSE, 5 );
    #$defs_f->set_shadow_type('none');

    my $defs_vbox = Gtk2::VBox->new;
    $defs_f->add($defs_vbox);

    my $label3 = Gtk2::Label->new;
    $defs_vbox->pack_start( $label3, FALSE, FALSE, 5 );
    $label3->set_text( gettext('Select a time to update your signatures.') );

    my $defs_hbox = Gtk2::HBox->new;
    $defs_vbox->pack_start( $defs_hbox, FALSE, FALSE, 0 );

    $hour_s_2 = Gtk2::SpinButton->new_with_range( 0, 24, 1 );
    $defs_hbox->pack_start( $hour_s_2, TRUE, TRUE, 5 );
    $hour_s_2->set_wrap(TRUE);
    $tt->set_tip( $hour_s_2, gettext('Set the hour using a 24 hour clock.') );
    my $hour_l_2 = Gtk2::Label->new( gettext('Hour') );
    $defs_hbox->pack_start( $hour_l_2, FALSE, TRUE, 5 );

    $min_s_2 = Gtk2::SpinButton->new_with_range( 0, 59, 1 );
    $min_s_2->set_wrap(TRUE);
    $defs_hbox->pack_start( $min_s_2, TRUE, TRUE, 5 );
    my $min_l_2 = Gtk2::Label->new( gettext('Minute') );
    $defs_hbox->pack_start( $min_l_2, FALSE, TRUE, 5 );

    my $defs_hbb = Gtk2::HButtonBox->new;
    $defs_vbox->pack_start( $defs_hbb, FALSE, FALSE, 0 );
    $defs_hbb->set_layout('end');

    my $defs_bar = Gtk2::Toolbar->new;
    $defs_vbox->pack_start( $defs_bar, FALSE, FALSE, 0 );
    $defs_bar->set_style('icons');

    my $bsep = Gtk2::SeparatorToolItem->new;
    $bsep->set_draw(FALSE);
    $bsep->set_expand(TRUE);
    $defs_bar->insert( $bsep, -1 );

    $defs_apply_btn = Gtk2::ToolButton->new_from_stock('gtk-add');
    $defs_bar->insert( $defs_apply_btn, -1 );
    $defs_apply_btn->signal_connect( 'clicked' => \&apply_defs );

    $defs_bar->insert( Gtk2::SeparatorToolItem->new, -1 );

    $defs_remove_btn = Gtk2::ToolButton->new_from_stock('gtk-remove');
    $defs_bar->insert( $defs_remove_btn, -1 );
    $defs_remove_btn->signal_connect(
        'clicked' => sub { remove('clamtk-defs') } );

    my $status_f = Gtk2::Frame->new( gettext('Status') );
    $vbox->pack_start( $status_f, FALSE, FALSE, 5 );
    #$status_f->set_shadow_type('none');

    my $stat_box = Gtk2::VBox->new( TRUE, 5 );
    $status_f->add($stat_box);

    $scan_status = Gtk2::Label->new;
    $stat_box->pack_start( $scan_status, FALSE, FALSE, 0 );
    $scan_status->set_text( gettext('A daily scan is scheduled.') );

    $defs_status = Gtk2::Label->new;
    $stat_box->pack_start( $defs_status, FALSE, FALSE, 0 );
    $defs_status->set_text(
        gettext('A daily definitions update is scheduled.') );

    my $end_bar = Gtk2::Toolbar->new;
    $vbox->pack_start( $end_bar, FALSE, FALSE, 0 );
    $end_bar->set_style('both-horiz');

    my $sep = Gtk2::SeparatorToolItem->new;
    $sep->set_draw(FALSE);
    $sep->set_expand(TRUE);
    $end_bar->insert( $sep, -1 );

    my $close_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $close_btn->set_is_important(TRUE);
    $end_bar->insert( $close_btn, -1 );
    $close_btn->signal_connect( 'clicked' => sub { $dialog->destroy } );

    $dialog->grab_focus();
    $dialog->show_all();

    is_enabled();
    Gtk2->main();
    return;
}

sub is_enabled {
    my ( $scan, $scan_hour, $scan_minute, $updates, $updates_hour,
        $updates_minute )
        = (0) x 6;
    my $excludes = 0;     # guess if user is ignoring whitelist or not
    my $target   = '';    # guess if scan involves Home or System

    open( my $L, '-|', $cmd, '-l' )
        or do {
        win_dialog('problem checking crontab listing in is_enabled');
        };

    while (<$L>) {
        Gtk2->main_iteration while ( Gtk2->events_pending );
        next if /^#/;
        next if /^\s*$/;
        chomp;
        my ( $min, $hour ) = split(/\s+/);
        if (/# clamtk-scan/) {
            $scan        = 1;
            $scan_hour   = $hour;
            $scan_minute = $min;
            $excludes++ while /--exclude/g;
            $target = (m#-r / #) ? 'system' : 'home';
        } elsif (/# clamtk-defs/) {
            $updates        = 1;
            $updates_hour   = $hour;
            $updates_minute = $min;
        }
    }
    close($L);

    if ($scan) {
        $hour_s->set_value($scan_hour);
        $min_s->set_value($scan_minute);
        $scan_apply_btn->set_sensitive(FALSE);
        $scan_remove_btn->set_sensitive(TRUE);
        $scan_status->set_text( gettext('A daily scan is scheduled.') );

        if ($target) {
            # We correctly (?) guessed the type of scan already set
            if ( $target eq 'system' ) {

                # system-wide scan
                $root_b->set_active(TRUE);
                if ( $excludes != 3 ) {

                    # There are three --exclude-dirs by default
                    # for system-wide scans
                    # This means the user is using whitelist
                    $ignore_white->set_active(FALSE);
                } else {
                    $ignore_white->set_active(TRUE);
                }
            } elsif ( $target eq 'home' ) {

                # home scan
                $home_b->set_active(TRUE);
                if ( $excludes == 0 ) {

                    # If there are zero --exclude-dirs
                    # This means the user is not using the whitelist
                    $ignore_white->set_active(TRUE);
                } else {
                    $ignore_white->set_active(FALSE);
                }
            }
        }
    } else {
        $scan_apply_btn->set_sensitive(TRUE);
        $scan_remove_btn->set_sensitive(FALSE);
        $scan_status->set_text( gettext('A daily scan is not scheduled.') );
    }

    if ($updates) {
        $hour_s_2->set_value($updates_hour);
        $min_s_2->set_value($updates_minute);
        $defs_apply_btn->set_sensitive(FALSE);
        $defs_remove_btn->set_sensitive(TRUE);
        $defs_status->set_text(
            gettext('A daily definitions update is scheduled.') );
    } else {
        $defs_apply_btn->set_sensitive(TRUE);
        $defs_remove_btn->set_sensitive(FALSE);
        $defs_status->set_text(
            gettext('A daily definitions update is not scheduled.') );
    }
    return;
}

sub apply_scan {
    my $hour = $hour_s->get_value;
    my $min  = $min_s->get_value;

    my ( $root, $home );

    my $paths = ClamTk::App->get_path('all');

    # This probably isn't necessary;
    # ensure old task is removed
    remove('# clamtk-scan');

    my $tmp_file = "$paths->{clamtk}" . "/" . "cron";
    open( my $T, '>', $tmp_file ) or do {
        win_dialog('Error opening temporary file');
        return;
    };

    open( my $L, '-|', $cmd, '-l' ) or do {
        win_dialog('Error opening crontab command');
        return;
    };

    while (<$L>) {
        Gtk2->main_iteration while ( Gtk2->events_pending );
        print $T $_;
    }
    close($L);
    close($T);

    my $full_cmd = $paths->{clamscan};
    $full_cmd =~ s/(.*?clamscan)\s.*/$1/;

    # Home directory chosen
    if ( $home_b->get_active ) {
        $home = "-r " . $paths->{directory};
        if ( $ignore_white->get_active ) {
            # The user wants to scan whitelisted directories
            # $home .= ' --exclude-dir=' . $paths->{viruses};
        } else {
            # The box is not checked; use the whitelist
            # So add the excludes
            $home .= ' --exclude-dir=' . $paths->{viruses};
            for ( split /;/, ClamTk::Prefs->get_preference('Whitelist') ) {
                $home .= ' --exclude-dir=' . quotemeta($_);
            }
        }
    }
    # The root (/) is chosen
    if ( $root_b->get_active ) {
        $root =
            '-r / --exclude-dir=/proc --exclude-dir=/sys --exclude-dir=/dev';
        if ( !$ignore_white->get_active ) {
            # The box is not checked; use the whitelist.
            # So, add the excludes:
            $root .= ' --exclude-dir=' . $paths->{viruses};
            for ( split /;/, ClamTk::Prefs->get_preference('Whitelist') ) {
                $root .= ' --exclude-dir=' . $_;
            }
        }
    }

    # Ignore mail directories until we can parse stuff
    for my $not_parse (
        qw| .thunderbird	.mozilla-thunderbird
        .evolution 	Mail	kmail |
        ) {
        $full_cmd .= ' --exclude-dir=' . $not_parse;
    }

    # Use the appropriate signatures
    if ( ClamTk::Prefs->get_preference('Update') eq 'single' ) {
        $full_cmd .= " --database=$paths->{db}";
    }

    # By default, look for PUA's
    $full_cmd .= " --detect-pua -i ";
    $full_cmd .= ( $home_b->get_active ) ? $home : $root;

    # Add the (ugly) logging
    $full_cmd .= ' --log="$HOME/.clamtk/history/$(date +\%b-\%d-\%Y).log"'
        . ' 2>/dev/null';

    open( $T, '>>', $tmp_file ) or do {
        win_dialog('Error opening temporary file');
        return;
    };
    print $T "$min $hour * * * $full_cmd # clamtk-scan\n";
    close($T);

    # reload crontab
    system( $cmd, $tmp_file ) == 0 or do {
        win_dialog('Error reloading cron file');
        unlink($tmp_file) or warn "Unable to delete tmp_file $tmp_file: $!\n";
        return;
    };
    is_enabled();
    return;
}

sub apply_defs {
    my $hour = $hour_s_2->get_value;
    my $min  = $min_s_2->get_value;

    my $paths = ClamTk::App->get_path('all');

    # this probably isn't necessary;
    # ensure old task is removed
    remove('# clamtk-defs');

    my $tmp_file = $paths->{clamtk} . "/" . "cron";
    open( my $T, '>', $tmp_file ) or do {
        win_dialog('Error opening temporary file');
        return;
    };

    open( my $L, '-|', $cmd, '-l' ) or do {
        win_dialog('Error opening crontab command');
        return;
    };

    while (<$L>) {
        Gtk2->main_iteration while ( Gtk2->events_pending );
        print $T $_;
    }
    close($L);
    close($T);

    my $full_cmd = $paths->{freshclam};

    if (ClamTk::Prefs->get_preference('Update') eq 'single'

        # The following is necessary if the user is not root, as
        # the update attempt will fail due to lack of permissions.
        # It's still not a good fix since the user might not realize it...
        # But with the ability to rerun the AV choice, it should work.
        || $> != 0
        ) {
        $full_cmd
            .= " --datadir=$paths->{db} --log=$paths->{db}/freshclam.log";
    }

    # Add config file if user has configured a proxy
    if ( ClamTk::Prefs->get_preference('HTTPProxy') ) {
        if ( ClamTk::Prefs->get_preference('HTTPProxy') == 2 ) {
            if ( -e "$paths->{db}/local.conf" ) {
                $full_cmd .= " --config-file=$paths->{db}/local.conf";
            }
        }
    }

    open( $T, '>>', $tmp_file ) or do {
        win_dialog('Error opening temporary file');
        return;
    };

    print $T "$min $hour * * * $full_cmd # clamtk-defs\n";
    close($T);

    # reload crontab

    system( $cmd, $tmp_file ) == 0 or do {
        win_dialog('Error reloading cron file');
    };
    unlink($tmp_file) or warn "Unable to delete tmp_file $tmp_file: $!\n";
    is_enabled();
    return;
}

sub remove {
    # $which = 'clamtk-scan' or 'clamtk-defs'
    my ($which) = shift;

    my $paths = ClamTk::App->get_path('clamtk');

    my $tmp_file = "$paths/cron";
    open( my $T, '>', $tmp_file ) or do {
        win_dialog('Error opening temporary file');
        return;
    };
    open( my $L, '-|', $cmd, '-l' ) or do {
        win_dialog('Error opening crontab');
        return;
    };

    while (<$L>) {
        Gtk2->main_iteration while ( Gtk2->events_pending );
        print $T $_ unless (/$which/);
    }
    close($L);

    # reload crontab
    system( $cmd, $tmp_file ) == 0 or do {
        win_dialog('Error reloading cron file');
    };
    unlink($tmp_file) or warn "Unable to delete tmp_file $tmp_file: $!\n";

    if ( $which eq 'clamtk-scan' ) {
        $hour_s->set_value('00');
        $min_s->set_value('00');
        # restore defaults = scan home drive and use whitelist
        $ignore_white->set_active(FALSE);
        $home_b->set_active(TRUE);
    } elsif ( $which eq 'clamtk-defs' ) {
        $hour_s_2->set_value('00');
        $min_s_2->set_value('00');
    }
    is_enabled();
    return;
}

sub win_dialog {
    my $get     = shift;
    my $message = "Sorry, there appears to have been an error.\n"
        . "Here is the message:\n";
    $message .= $get;
    my $popup;
    $popup =
        Gtk2::MessageDialog->new_with_markup( undef,
        [qw(modal destroy-with-parent)],
        'error', 'close', $message );

    $popup->run;
    $popup->destroy;
    return;
}

1;

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
package ClamTk::Update;

# use strict;
# use warnings FATAL => 'all';
$| = 1;

use LWP::UserAgent;

use File::Copy 'copy';
use Locale::gettext;
use POSIX 'locale_h';

use Gtk2::SimpleList;
use Glib 'TRUE', 'FALSE';

my ( $win, $update_list );
my ( $go_btn, $close_btn, $cancel_btn );
my ($update_sig_pid);

sub update_dialog {
    # These are the main $window's x/y coordinates.
    # Seems to work intermittently, and possibly
    # less expensive than sending $window itself.
    # The ->move below shifts it to those coordinates.
    my ( undef, $x, $y ) = @_;
    $win = Gtk2::Dialog->new();
    $win->signal_connect( destroy => sub { $win->destroy; } );
    $win->set_title( gettext('Virus Scanner') );
    $win->set_default_size( 625, 130 );
    $win->move( $x, $y );

    if ( -e '/usr/share/pixmaps/clamtk.png' ) {
        $win->set_default_icon_from_file('/usr/share/pixmaps/clamtk.png');
    } elsif ( -e '/usr/share/pixmaps/clamtk.xpm' ) {
        $win->set_default_icon_from_file('/usr/share/pixmaps/clamtk.xpm');
    }

    my $tt = Gtk2::Tooltips->new();

    my $update_win = Gtk2::ScrolledWindow->new();
    $win->vbox->pack_start( $update_win, TRUE, TRUE, 0 );
    $update_win->set_policy( 'never', 'never' );
    $update_win->set_shadow_type('etched-out');

    $update_list = Gtk2::SimpleList->new(
        gettext('Updates')     => 'text',
        gettext('Description') => 'text',
        gettext('Select')      => 'bool',
        gettext('Status')      => 'text',
        );
    $update_win->add($update_list);
    $update_win->grab_focus();

    my $sig_box = Gtk2::CheckButton->new();
    $sig_box->set_active(FALSE);
    if ( $> != 0 ) {
        $sig_box->set_sensitive(FALSE);
        $tt->set_tip( $sig_box, gettext('You must be root to enable this.') );
    }

    my $gui_box = Gtk2::CheckButton->new();

    my $user_can = 0;
    if ( ClamTk::Prefs->get_preference('Update') eq 'single' ) {
        $user_can = 1;
    }

    my $paths = ClamTk::App->get_path('all');

    # Add signature updates as an option IF
    # the user is root, or has opted to do it manually
    if ( $> == 0 || $user_can ) {
        if ( $paths->{freshclam} ) {
            push @{ $update_list->{data} },
                [
                gettext('Signature updates'),
                gettext('Check for antivirus signature updates'),
                $sig_box, gettext('N/A'),
                ];
        }
    }

    # Add option to check for GUI updates
    push @{ $update_list->{data} },
        [
        gettext('GUI updates'),
        gettext('Check for updates to the graphical interface'),
        $gui_box, gettext('N/A'),
        ];

    # This box will hold buttons to check for updates, cancel,
    # close the window, and if the user's root, warn them.
    my $choicebar = Gtk2::Toolbar->new();
    $choicebar->set_style('both-horiz');
    $win->vbox->pack_start( $choicebar, FALSE, FALSE, 0 );
    $win->vbox->set_focus_child($choicebar);

    my $u_sep = Gtk2::SeparatorToolItem->new;
    $u_sep->set_draw(FALSE);
    $u_sep->set_expand(TRUE);
    $choicebar->insert( $u_sep, -1 );

    # Check for updates button
    $go_btn = Gtk2::ToolButton->new_from_stock('gtk-network');
    $go_btn->set_is_important(TRUE);
    $go_btn->set_expand(FALSE);
    $go_btn->set_label( gettext('Check for updates') );
    $go_btn->signal_connect( clicked => \&decision );
    $choicebar->insert( $go_btn, -1 );

    $choicebar->insert( Gtk2::SeparatorToolItem->new, -1 );

    # Close window button
    $close_btn = Gtk2::ToolButton->new_from_stock('gtk-close');
    $close_btn->set_is_important(TRUE);
    $close_btn->set_expand(FALSE);
    $close_btn->signal_connect(
        clicked => sub {
            $update_win->destroy;
            $win->destroy;
        } );
    $choicebar->insert( $close_btn, -1 );

    $choicebar->insert( Gtk2::SeparatorToolItem->new, -1 );

    # Cancel button
    $cancel_btn = Gtk2::ToolButton->new_from_stock('gtk-cancel');
    $cancel_btn->set_is_important(TRUE);
    $cancel_btn->set_expand(FALSE);
    $cancel_btn->signal_connect(
        clicked => sub {
            kill 15, $update_sig_pid if ($update_sig_pid);
            waitpid( $update_sig_pid, 0 );
            $update_sig_pid            = '';
            $update_list->{data}[0][3] = gettext('N/A');
            $update_list->{data}[1][3] = gettext('N/A');
            $go_btn->set_sensitive(TRUE);
            $close_btn->set_sensitive(TRUE);
            $cancel_btn->set_sensitive(FALSE);
        } );
    $choicebar->insert( $cancel_btn, -1 );
    $cancel_btn->set_sensitive(FALSE);

    # Warn the user not to do things as root.
    if ( $> == 0 ) {
        my $warning_btn =
            Gtk2::ToolButton->new_from_stock('gtk-dialog-warning');
        $choicebar->insert( $warning_btn, -1 );
        $warning_btn->signal_connect(
            clicked => sub {
                my $message = gettext(
                    "It is recommended you do not run this application as root.\n"
                        . 'Please see http://clamtk.sf.net/faq.html.' );
                my $dialog =
                    Gtk2::MessageDialog->new( $win,
                    [qw(modal destroy-with-parent)],
                    'warning', 'close', $message );

                $dialog->run;
                $dialog->destroy;
            } );
    }

    # Rotate (actually truncate) user's freshclam.log
    # We'll just keep about 30 lines for the regular user
    # since root will (hopefully) use the system's area which
    # will already do log rotation.
    # The 30 lines will be useful for diagnosing problems.
    # Don't rotate if TruncateLog=0
    # This should only be expensive the first time or if the user
    # has automatic (cron) updates scheduled and doesn't come here often.
    if ( $> != 0 && ClamTk::Prefs->get_preference('TruncateLog') ) {
        my $log = "$paths->{db}/freshclam.log";
        if ( open( my $f, '<', $log ) ) {
            my $tmp_file = "$paths->{db}/temp.tmp";
            my @log      = ();
            @log = <$f>;
            close($f);
            if ( scalar(@log) > 30 ) {
                open( my $t, '>', $tmp_file )
                    or last;
                for ( -30 .. 0 ) {
                    print $t $log[$_];
                }
                close($t);
                rename( $tmp_file, $log );
                unlink($tmp_file);
            }
        }
    }

    $win->show_all();
    $win->run;
    $win->destroy;
    return;
}

sub decision {
    my ( $rowref, $scalar );
    $scalar = scalar( @{ $update_list->{data} } );
    return unless ($scalar);
    my $value = 0;
    $go_btn->set_sensitive(FALSE);
    $close_btn->set_sensitive(FALSE);
    $cancel_btn->set_sensitive(TRUE);
    $win->queue_draw;

    # Go through the rows of options
    for my $row ( 0 .. $scalar - 1 ) {
        Gtk2->main_iteration while Gtk2->events_pending;
        $rowref = $update_list->{data}[$row];
        # Find out if that option is enabled
        if ( $rowref->[2] == 1 ) {
            if ( $rowref->[0] eq gettext('Signature updates') ) {
                $update_list->{data}[$row][3] = gettext('Checking...');
                $value = update_signatures($row);
                $update_list->{data}[$row][3] =
                      $value == -1 ? gettext('Update failed')
                    : $value == 1  ? gettext('Signatures are current')
                    : $value == 2  ? gettext('Updated')
                    :                '';
                ClamTk::GUI->set_sig_status();
            } elsif ( $rowref->[0] eq gettext('GUI updates') ) {
                $update_list->{data}[$row][3] = gettext('Checking...');
                $value = update_gui( 'dummy', 'not-startup' );
                $update_list->{data}[$row][3] =
                      $value == 1 ? gettext('Current')
                    : $value == 2 ? gettext('A newer version is available')
                    : $value == 3 ? gettext('Current')
                    : $value == 4 ? gettext('Check failed')
                    : $value == 5 ? gettext('Check failed')
                    :               '';
                ClamTk::GUI->set_tk_status($value);
            } else {
                #warn 'ref = ', $rowref->[0], "\n";
            }
        }
    }
    $win->resize( 625, 130 );
    $win->queue_draw;
    $go_btn->set_sensitive(TRUE);
    $close_btn->set_sensitive(TRUE);
    $cancel_btn->set_sensitive(FALSE);
    return;
}

sub update_signatures {
    my $print_row = shift;
    Gtk2->main_iteration while Gtk2->events_pending;
    $win->queue_draw;

    # return code:
    # -1 = failed, 1 = current, 2 = has been updated

    my $paths = ClamTk::App->get_path('all');

    my $command = $paths->{freshclam};
    # If the user will update the signatures manually,
    # append the appropriate paths
    if ( ClamTk::Prefs->get_preference('Update') eq 'single' ) {
        $command
            .= " --datadir=$paths->{db} --log=$paths->{db}/freshclam.log";
    }

    # Did the user set the proxy option?
    if ( ClamTk::Prefs->get_preference('HTTPProxy') ) {
        if ( ClamTk::Prefs->get_preference('HTTPProxy') == 2 ) {
            if ( -e "$paths->{db}/local.conf" ) {
                $command .= " --config-file=$paths->{db}/local.conf";
            }
        }
    }

    # The mirrors can be slow sometimes and may return/die
    # 'failed' despite that the update is still in progress.
    my $update;
    eval {
        local $SIG{ALRM} = sub { die "failed\n" };
        alarm 60;

        $update_sig_pid = open( $update, '-|', "$command --stdout" );
        defined($update_sig_pid) or return -1;
        alarm 0;
    };
    if ( $@ && $@ eq "failed\n" ) {
        return -1;
    }

    # We don't want to print out the following lines beginning with:
    my $do_not_print = "DON'T|WARNING|ClamAV update process";

    # We can't just print stuff out; that's bad for non-English
    # speaking users. So, we'll grab the first couple words
    # and try to sum it up.

    while ( defined( my $line = <$update> ) ) {
        Gtk2->main_iteration while ( Gtk2->events_pending );

        # skip the bad stuff
        next if ( $line =~ /$do_not_print/ );
        chomp($line);

        # $final is the gettext-ed version
        my $final = '';

        if ( $line =~ /^Trying host/ ) {
            $final = gettext('Trying to connect...');
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
        } elsif ( $line =~ /Downloading daily|Retrieving http/ ) {
            $final = gettext('Downloading updates...');
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
        } elsif ( $line =~ /nonblock_connect|Can't connect to/ ) {
            $final = gettext('Cannot connect...');
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
        } elsif ( $line =~ /^daily.c.d updated/ ) {
            $final = gettext('Daily signatures have been updated');
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
        } elsif ( $line =~ /Database updated .(\d+) signatures/ ) {
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
            return 2;
        } elsif ( $line =~ /daily.c.d is up to date/ ) {
            Gtk2->main_iteration while ( Gtk2->events_pending );
            return 1;
        } elsif ( $line =~ /main.cvd version from DNS/ ) {
            $final = gettext('Checking main virus database version');
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
        } elsif ( $line =~ /main.c.d is up to date/ ) {
            $final = gettext('Main virus database is current');
            Gtk2->main_iteration while ( Gtk2->events_pending );
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
        } elsif ( $line =~ /Update failed/ ) {
            $final = gettext('Update failed');
            $update_list->{data}[$print_row][3] = $final;
            Gtk2->main_iteration while ( Gtk2->events_pending );
            return -1;
        } else {
            next;
        }
        Gtk2->main_iteration while ( Gtk2->events_pending );
        $win->queue_draw;
    }

    # We could try closing the filehandle <$update>,
    # but it will go out of scope anyway.
    return;
}

sub update_gui {
    my ( undef, $caller ) = @_;

    my ($version) = ClamTk::App->get_TK_version();

    if ( $caller and $caller eq 'startup' ) {
        # The user may have set the preference ('GUICheck')
        # to not check this on startup
        return 5
            unless ( ClamTk::Prefs->get_preference('GUICheck') );
    }

    # return code:
    # -1 = failed, 1 = current, 2 = not current, 3 = too updated

    # We'll remove everything but the numbers
    # from both the local and remote versions to compare
    $version =~ s/[^0-9]//g;

    my $ua = LWP::UserAgent->new;
    $ua->timeout(10);
    if ( ClamTk::Prefs->get_preference('HTTPProxy') ) {
        if ( ClamTk::Prefs->get_preference('HTTPProxy') == 1 ) {
            $ua->env_proxy;
        } elsif ( ClamTk::Prefs->get_preference('HTTPProxy') == 2 ) {
            my $path = ClamTk::App->get_path('db');
            $path .= '/local.conf';
            my ( $url, $port );
            if ( -e $path ) {
                if ( open( my $FH, '<', $path ) ) {
                    while (<$FH>) {
                        if (/HTTPProxyServer\s+(.*?)$/) {
                            $url = $1;
                        }
                        last if ( !$url );
                        if (/HTTPProxyPort\s+(\d+)$/) {
                            $port = $1;
                        }
                    }
                    close($FH);
                    $ua->proxy( http => "$url:$port" );
                }
            }
        }
    }

    my $response = $ua->get('http://clamtk.sourceforge.net/latest');

    if ( $response->is_success ) {
        my $content = $response->content;
        chomp($content);
        $content =~ s/[^0-9]//g;
        return 1 if ( $version == $content );    # current
        return 2 if ( $content > $version );     # outdated
        return 3 if ( $version > $content );     # too current?
        return 4;                                # shouldn't happen
    } else {
        # warn $response->as_string, "\n";
        return 5;                                # failed, unable to check
    }
}

sub av_db_select {
    # This is an easy way for the user to switch back
    # and forth their preferred way to update signatures.

    # These are the main $window's x/y coordinates.
    # Seems to work intermittently, and possibly
    # less expensive than sending $window itself.
    # The ->move below shifts it to those coordinates.
    my ( undef, $x, $y ) = @_;

    my $assistant = Gtk2::Assistant->new;
    #$assistant->set_default_size( -1, 240 );
    $assistant->move( $x, $y );

    # What the user already has - and then chooses.
    # We'll declare it now because of the button toggle action.
    my $pref = '';

    # This is the first page.
    my $abox = Gtk2::VBox->new( FALSE, 12 );
    $abox->set_border_width(12);

    # dlabel holds the main text (dialog)
    my $dlabel = Gtk2::Label->new;
    my $dialog;
    $dialog .= gettext(
        'Please choose how you will update your antivirus signatures.');
    $dialog .= "\n\n";
    $dialog
        .= gettext( 'If you would like to update the signatures yourself, '
            . 'choose Manual.' );
    $dialog .= "\n\n";
    $dialog
        .= gettext(
        'If your computer automatically receives updates, choose Automatic.'
        );
    $dialog .= "\n";
    $dlabel->set_text($dialog);

    $abox->pack_start( $dlabel, FALSE, FALSE, 0 );

    # This ButtonBox will hold the manual/automatic option.
    my $choice_bb = Gtk2::HButtonBox->new;
    $abox->pack_start( $choice_bb, FALSE, FALSE, 0 );
    # The 'center' layout might be nicer, but CentOS 5.x has
    # an older version of Gtk2 apparently, so we'll use 'spread'.
    $choice_bb->set_layout('spread');

    # Manually update the sigs
    my $manual_btn =
        Gtk2::RadioButton->new_with_label( undef, gettext('Manual') );
    $choice_bb->add($manual_btn);
    $manual_btn->signal_connect(
        toggled => sub {
            $pref = 'single';
        } );

    # Automatically update the sigs.
    # This is the default, out-of-the-box choice.
    my $auto_btn =
        Gtk2::RadioButton->new_with_label( $manual_btn->get_group,
        gettext('Automatic') );
    $choice_bb->add($auto_btn);
    $auto_btn->signal_connect(
        toggled => sub {
            $pref = 'shared';
        } );

    # We'll start with what the user currently has selected
    # as their update preference.
    $pref = ClamTk::Prefs->get_preference('Update');
    # Just in case, set it to 'shared' if nothing else:
    $pref ||= 'shared';

    if ( $pref eq 'shared' ) {
        $auto_btn->set_active(TRUE);
    } elsif ( $pref eq 'single' ) {
        $manual_btn->set_active(TRUE);
    }

    $assistant->append_page($abox);
    $assistant->set_page_title( $abox,
        gettext('Antivirus signature options') );

    # Although easy enough to use the ClamTk png for this,
    # we'll just use default question/info images.
    my $pixbuf = $abox->render_icon( 'gtk-dialog-question', 'dialog' );
    $assistant->set_page_side_image( $abox, $pixbuf );

    # The 'confirm' style is necessary for the 'apply' button.
    $assistant->set_page_type( $abox, 'confirm' );
    # There's an option already there, so set it complete no matter what.
    $assistant->set_page_complete( $abox, TRUE );

    # The Assistant's signals/callbacks
    $assistant->signal_connect(
        cancel => sub {
            $assistant->destroy;
        } );
    $assistant->signal_connect(
        close => sub {
            $assistant->destroy;
        } );
    $assistant->signal_connect(
        apply => sub {
            save( $auto_btn->get_active ? 'shared' : 'single' );
            # Update status of signatures.  The date and status
            # (Current/Outdated) may have changed when switching.
            ClamTk::GUI->set_sig_status();
        } );

    # This is the second page: 'confirm' or confirmation.
    my $comp_page = Gtk2::Alignment->new( 0.5, 0.5, 0.5, 0.0 );

    # Not much else to say...
    my $label = Gtk2::Label->new( gettext('Your preferences were saved.') );
    $comp_page->add($label);

    $assistant->append_page($comp_page);
    $assistant->set_page_title( $comp_page,
        gettext('Antivirus signature options') );
    $assistant->set_page_type( $comp_page, 'summary' );
    $assistant->set_page_complete( $abox, TRUE );

    # Now switch the image to 'info'.
    $pixbuf = $abox->render_icon( 'gtk-dialog-info', 'dialog' );
    $assistant->set_page_side_image( $comp_page, $pixbuf );

    $assistant->show_all();
    return;
}

sub save {
    my $update = shift;

    my ($ret) = ClamTk::Prefs->set_preference( 'Update', $update );

    if ( $ret == 1 ) {
        # It worked, so see if there are system signatures around
        # we can copy to save bandwidth and time
        my $paths = ClamTk::App->get_path('db');

        if ( $update eq 'single' ) {
            my ( $d, $m ) = (0) x 2;
            Gtk2->main_iteration while ( Gtk2->events_pending );
            for my $dir_list (
                '/var/clamav',             '/var/lib/clamav',
                '/opt/local/share/clamav', '/usr/share/clamav',
                '/usr/local/share/clamav', '/var/db/clamav',
                ) {
                if ( -e "$dir_list/daily.cld" ) {
                    copy( "$dir_list/daily.cld", "$paths/daily.cld" );
                    $d = 1;
                } elsif ( -e "$dir_list/daily.cvd" ) {
                    copy( "$dir_list/daily.cvd", "$paths/daily.cvd" );
                    $d = 1;
                }
                if ( -e "$dir_list/main.cld" ) {
                    copy( "$dir_list/main.cld", "$paths/main.cld" );
                    $m = 1;
                } elsif ( -e "$dir_list/main.cvd" ) {
                    copy( "$dir_list/main.cvd", "$paths/main.cvd" );
                    $m = 1;
                }
                last if ( $d && $m );
            }
        }
    }
    return;
}

1;

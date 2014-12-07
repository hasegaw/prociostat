#!/usr/bin/perl
#
# prociostat.pl
# $Id$
#

use Getopt::Std;
use Data::Dumper;

my $filter = {};

sub read_file_string {
	my $file = shift;
	open(F, $file) || return undef;
	my @l = <F>;
	close(F);

	if (@l + 0 > 1) {
		return \@l;
	}
	return shift(@l);
}

sub read_file_int {
	my $file = shift;
	return read_file_string($file) + 0;
}


sub read_proc_pid_stat {
	my $pid = shift;
	open(F, sprintf("/proc/%d/stat", $pid)) || return undef;
	my $l;
	while ($l = <F>) {
	
	#1 (init) S 0 1 1 0 -1 4202752 3184 54586547 16 9952 5 61 711087 212578 20 0 1 0 1 24166400 384 18446744073709551615 1 1 0 0 0 0 0 4096 536962595 18446744073709551615 0 0 0 3 0 0 64 0 0	
#		print $l. "\n";
		$l =~ /([-0-9]+) (.*) ([RSDZTW]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+) ([-0-9]+)/;
		my @a = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
			$21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
			$31, $32, $33, $34, $35, $36, $37, $38, $39,
			$40, $41, $42, $43, $44
		);

		my $p = {};

		@b = qw/pid comm state ppid pgrp session tty_nr tggid flags minflt cminflt majflt cmajflt utime stime cutime cstime priority nice num_threads itrealvalue starttime vsize rss rsslim startcode endcode startstack kstkesp kstkeip signal blocked sigignore sigcatch wchan nswap cnswap exit_signal processor rt_priority policy delayacct_blkio_ticks guest_time cguest_time/;

#		print Dumper(@a);
#		print Dumper(@b);
		for my $f (@b) {
			$p->{$f} = shift @a;
		}
		return $p;
	}
}

sub read_proc_pid_io {
	my $pid = shift;
	my $r = {};
	my $l;

	read_proc_pid_stat($pid);

	open(PID, sprintf("/proc/%d/io", $pid)) || return undef;
	my @lines = <PID>;
	close(PID);
	foreach $f (qw/loginuid/) {
		$r->{$f} = read_file_int(sprintf("/proc/%d/%s", $pid, $f));
	}
	foreach $f (qw/cmdline stat/) {
		$r->{$f} = read_file_string(sprintf("/proc/%d/%s", $pid, $f));
	}
	$r->{stat} = read_proc_pid_stat($pid);

	foreach $l (@lines) {
		chomp $l;
#		print Dumper ($l);
		my ($f, $d) = split(/: /, $l);
		$r->{$f} = $d;
	}

#	print Dumper($r);
	return $r;
}

sub filter_pid_check($) {
	my $pid = shift;
	return 0 if ((defined $filter->{pid_min}) && ($pid < $filter->{pid_min}));
	return 0 if ((defined $filter->{pid_max}) && ($pid > $filter->{pid_max}));
	return 1;
}

sub filter_uid_check($) {
	my $uid = shift;
	return 0 if ((defined $filter->{uid_min}) && ($pid < $filter->{uid_min}));
	return 0 if ((defined $filter->{uid_max}) && ($pid > $filter->{uid_max}));
	return 1;
}

sub get_active_pids {
	opendir(DIR, "/proc/") || die;

	my @dirs = ();

	while ($dir = readdir(DIR)) {
		next if ($dir =~ /[^0-9]+/);
		push @dirs, ($dir + 0);
	}	
	closedir(DIR);
	return \@dirs;
}

sub get_active_processes {
	my @dirs = @{get_active_pids()};
	my $active_processes = {};

	foreach my $pid (@dirs) {
		next if (! filter_pid_check($pid));
		my $io = read_proc_pid_io($pid) || next;
		next if (! filter_uid_check($io->{loginuid}));
		$active_processes->{$pid} = $io;
	}
	return $active_processes;
}

# Singnal handler.
sub CB_SIGINT {
	$loop = 0;
}

sub calc_process_delta($$) {
	my $last_process = shift;
	my $current_process = shift;

	my $r = {};
	my $f;
	foreach $f (qw/read_bytes write_bytes/) {
		$r->{'delta_' . $f} = $current_process->{$f} - $last_process->{$f};
		$r->{'delta_' . $f} = 0 if (not defined $last_process->{$f});
	}


	# /proc/$pid/stat fields to get diff
	foreach $f (qw/utime stime delayacct_blkio_ticks/) {
		$r->{'delta_'.$f} = $current_process->{'stat'}->{$f} - $last_process->{'stat'}->{$f};
	}

	foreach $f (qw/comm pid ppid pgrip/) {
		$r->{$f} =  $current_process->{'stat'}->{$f};
	}

	return $r;
}

sub write_process_delta($$$) {
	my $ref_process_tree = shift;
	my $last_processes = shift;
	my $current_processes = shift;
	my $time = time;

	for my $pid (keys %{$current_processes}) {
		my $delta = calc_process_delta(
			$last_processes->{$pid},
			$current_processes->{$pid}
		);

		if (defined $options->{write_csv}) {
			my $header = ( ! -e 'process.'. $pid . '.txt' );
			my @csv = ($time, $delta->{delta_utime}, $delta->{delta_stime}, $delta->{delta_delayacct_blkio_ticks},
					 $delta->{delta_read_bytes}, $delta->{delta_write_bytes});

			open(CSV, '+>>process.'. $pid . '.txt');
			print CSV "time,delta_utime,delta_stime,delta_delayacct_blkio_ticks,delta_read_bytes,delta_write_bytes\n" if $header;
			print CSV join(',', @csv) . "\n";
			close(CSV);
		}
	}
}

sub show_dead_processes($$) {
	my $last_processes = shift;
	my $current_processes = shift;

	for my $pid (keys %{$last_processes}) {
		$p =  $last_processes->{$pid};

		if (not defined $current_processes->{$pid}) {
			$p =  $last_processes->{$pid};
			printf("pid %5d uid %5d user %6.2f sys %6.2f r %12d w %12d cmd %s\n",
					$pid, $p->{loginuid}, $p->{'stat'}->{utime} / 100, $p->{'stat'}->{stime} / 100, 
					$p->{read_bytes}, $p->{write_bytes},
					$p->{cmdline});
		}

		if (defined $options->{write_summary}) {
			# not implemented
		}
	}
}


my %opts;
getopts("ACSp:u:v", \%opts);

if ($opts{p} =~ /^(\d+)-(\d+)$/) {
	($filter->{pid_min}, $filter->{pid_max}) = sort ($1, $2);
} elsif ($opts{p} =~ /^(\d+)$/) {
	($filter->{pid_min}, $filter->{pid_max}) = ($1, $1);
} elsif(not defined $opts{p}) {
	# nop
} else {
	die "unsupported format : -p $opts{p}"	;
}	

if ($opts{u} =~ /^(\d+)-(\d+)$/) {
	($filter->{uid_min}, $filter->{uid_max}) = sort ($1, $2);
} elsif ($opts{u} =~ /^(\d+)$/) {
	($filter->{uid_min}, $filter->{uid_max}) = ($1, $1);
} elsif(not defined $opts{u}) {
	# nop
} else {
	die "unsupported format : -u $opts{u}"	;
}	

if ($opts{A}) {
	$options->{absolute} = 1;
}

if ($opts{C}) {
	$options->{write_csv} = 1;
}

if ($opts{S}) {
	$options->{write_summary} = 1;
}


$loop = 1;
$SIG{'INT'} = \&CB_SIGINT;
$SIG{'QUIT'} = \&CB_SIGINT;

my $last_processes = {};

while ($loop) {
	my $current_processes = get_active_processes();

	show_dead_processes($last_processes, $current_processes);
	write_process_delta($bibibi, $last_processes, $current_processes);

	sleep (1);
	$last_processes = $current_processes;
}
print "Bye!\n";
show_dead_processes($last_processes, {});


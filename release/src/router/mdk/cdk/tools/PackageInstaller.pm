################################################################################
#
#
#
package PackageInstaller;

use File::Path;
use File::Copy;
use File::Basename;
use File::Find; 

use strict; 

sub new 
{    
    my ($class, $pkg_dir, $ignore_version, $use_symlinks, $debug_level) = @_;
    my $self = {};
    bless($self, $class);
    $self->{pkg_dir} = $pkg_dir;
    $self->{ignore_version} = $ignore_version;
    $self->{use_symlinks} = $use_symlinks;
    $self->{debug_level} = $debug_level;
    $self;
}

my @ALL_PKG_DIRS; 

sub pkginfo_find
  {
    if($_ eq "PKGINFO") {
      push @ALL_PKG_DIRS, $File::Find::dir; 
    }
  }

sub release_packages
  {
    my $self = shift; 

    $#ALL_PKG_DIRS = -1; 
    find(\&pkginfo_find, $self->{pkg_dir}); 
    
    foreach my $dir (@ALL_PKG_DIRS) {
      my $pkginfo = $self->package_info("$dir/PKGINFO"); 
      if(defined($pkginfo->{DISABLED}) || defined($pkginfo->{NORELEASE})) {
        printf("RELPKGS: $dir removed\n"); 
        $self->remove_file($dir); 
      }
    }
  }
  
sub error_exit
{
    my $self = shift; 
    printf STDERR @_;
    exit 2;
}

sub info_msg
{
    my $self = shift; 
    printf @_;
}

sub verbose_msg
{
    my $self = shift; 
    if ($self->{debug_level} > 0) {
        printf @_;
    }
}

sub copy_file
{
    my ($self, $src, $dst) = @_;

    return copy($src, $dst);
}

sub symlink_file
{
    my ($self, $src, $dst) = @_;

    if ($self->{use_symlinks}) {
        return symlink($src, $dst);
    }
    return copy($src, $dst);
}

sub move_file
{
    my ($self, $src, $dst) = @_;

    return move($src, $dst);
}

sub make_path
{
    my ($self, $path) = @_;

    if (mkpath($path)) {
        $self->verbose_msg("Created directory $path\n");
    }
    else {
        $self->error_exit("Error creating directory $path\n");
        exit 1;
    }
}

sub remove_file
{
    my ($self, $path) = @_;

    if (rmtree($path)) {
        $self->verbose_msg("Removed $path\n");
    }
    else {
        $self->error_exit("Error removing $path\n");
        exit 1;
    }
}

sub install_file
{
    my ($self, $src, $dst) = @_;
    my $symlink_exists = eval { symlink("",""); 1 };
    my $cpfunc;

    if ($src =~ /\.tmp/) {
        $cpfunc = \&move_file;
    }
    else {
        $cpfunc = ($symlink_exists) ? \&symlink_file : \&copy_file;
    }
    if ($cpfunc->($self, $src, $dst)) {
        my $file = basename($dst);
        $self->verbose_msg("$file\n");
    }
    else {
        $self->error_exit("Error installing $dst\n");
    }
}

sub package_info {
    my ($self, $pkgfile) = @_;
    my $pkginfo;

    if (!open(PKGFILE, $pkgfile)) {
        $self->error_exit("Package file $pkgfile not found\n");
    }
    my @lines = <PKGFILE>;
    foreach my $line (@lines) {
	$line =~ s/\s+$//;
        my @config = split(/:/, $line);
        $pkginfo->{@config[0]} = @config[1];
    }
    close(PKGFILE);

    return $pkginfo;
}

sub get_pkg_list {
    my ($self, $pkgtype, $getall, $pkglistfile) = @_;
    my @pkglist = ();

    if (!($getall)) {
        if (!defined($pkglistfile)) {
            $pkglistfile = "$self->{pkg_dir}/$pkgtype-list";
        }
        if (open(PKGLISTFILE, "$pkglistfile")) {
            my @pkgtypelines = <PKGLISTFILE>;
            foreach my $line (@pkgtypelines) {
                $line =~ s/\s+$//;
                next if ($line =~ /^\#/);
                next if ($line eq "");
                if ($line eq "none") {
                    return ();
                }
                push @pkglist, $line;
            }
            close(PKGLISTFILE);
        }
    }

    if (@pkglist == 0) {
        my $pkgtypedir = "$self->{pkg_dir}/$pkgtype";
        if (opendir(PKGTYPEDIR, "$pkgtypedir")) {
            while (my $pkg = readdir(PKGTYPEDIR)) {
                next if ($pkg =~ /^CVS/);
                next if ($pkg =~ /^\./);
                push @pkglist, $pkg;
            }
            closedir(PKGTYPEDIR);
        }
    }
    return @pkglist;
}

sub read_stub_file {
    my ($self, $file) = @_;

    if (!open(STUBFILE, $file)) {
        $self->error_exit("Unable to open $file\n");
    }
    my @lines = <STUBFILE>;
    close(STUBFILE);

    return @lines;
}

sub check_version {
    my ($self, $pkg, $basever, $pkgver) = @_;

    if (!defined($pkg)) {
        $self->error_exit("Undefined package\n");
    }
    if (!defined($basever)) {
        $self->error_exit("No base version found for package $pkg\n");
    }
    if ($pkgver ne $basever && $pkgver !~ /^$basever\./) {
        if ($self->{ignore_version}) {
            $self->info_msg("Ignoring wrong patch level $pkgver for package $pkg\n");
        }
        else {
            $self->error_exit("Wrong patch level $pkgver for package $pkg\n");
        }
    }
}

1; 

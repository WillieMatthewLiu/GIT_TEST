#! /usr/bin/perl

use File::Basename;

@protocols=();

foreach (@ARGV) {
	$file = $_;
    ($name,$path,$suffix) = fileparse($file,'\.c');
    $count=@protocols;
    $protocols[$count] = $name;
}

print <<EOF;
int filter_init()
{
EOF

$count=1;
while($count < @protocols){
	print "    $protocols[$count]";
	print "_pktfilter_reg();\n";
	$count++;
}

print <<EOF;

    return pktfilter_init();
}

int filter_free()
{
    pktfilter_exit();
EOF

$count=1;
while($count < @protocols){
	print "    $protocols[$count]";
	print "_pktfilter_unreg();\n";
	$count++;
}

print <<EOF;
}
EOF
#!/bin/sh
trap "rm -f gap.pad gap.hv gap.ck gap.img xaa xab; exit" INT TERM EXIT
gap_bin=$1
cur_dir=`pwd`

if [ $# -eq 0 ];then
	echo "Please enter the parameter"
	exit
fi

platform_name=`uname -m`
if [ $platform_name == "mips64" -o $platform_name == "ppc64" ]; then
	mips_flag=1
else
	mips_flag=0
fi

rm -f  gap.pad gap.hv gap.ck gap.img xaa xab

vhead_size=`ls -l $gap_bin | awk '{print $5}'`

if [ $vhead_size -le 5122 ];then
	echo "file too small"
	exit
fi 

let "vpad_size=$vhead_size-4096-1024-2"


dd if=$gap_bin bs=1 skip=$vpad_size count=4096 of=gap.pad > /dev/null 2>&1

ver_cnt=`cat gap.pad | grep "version" | wc -l`
alg_cnt=`cat gap.pad | grep "algorithm" | wc -l`

if [ $ver_cnt -gt 0 ];then
	cat gap.pad | jq '.version' | xargs echo "gap Version:"
else
	echo "gap version:"
fi

if [ $alg_cnt -gt 0 ];then
	cat gap.pad | jq '.algorithm' | xargs echo "algorithm:"
else
	echo "algorithm:"
fi

let "ckpad_size=$vpad_size+4096"
dd if=$gap_bin bs=1 skip=$ckpad_size count=1024 of=gap.ck > /dev/null 2>&1
hexstr=`hexdump gap.ck  | grep 0000000 | sed -e "s/0000000 //" | sed -e "s/ //g"`

i=0
len=${#hexstr}

while [ $i -lt $len ]
do
        temp=`expr $i \% 2`
	temp_4=`expr $i \% 4`
	if [ $temp_4 -lt 2 ];then
        	pre_ck=${pre_ck}${hexstr:$i:1}
	else
	        if [ $temp -eq 0 ]; then
        	        sufix_ck=${hexstr:$i:1}
        	else
                	sufix_ck=${sufix_ck}${hexstr:$i:1}
        		if [ $mips_flag -eq 0 ];then
				checksum=${checksum}${sufix_ck}${pre_ck}
			else
				checksum=${checksum}${pre_ck}${sufix_ck}
			fi
			pre_ck=""
			sufix_ck=""
        	fi
		
	fi
	let i++
done


split -b $ckpad_size ${gap_bin}
newck=`md5sum xaa`
newck=`echo $newck | sed -e "s/ xaa$//"`


echo "Binary file checksum :"$checksum
echo "Calculated checksum  :"$newck

if [ $newck == $checksum ]; then
	echo "Image is correct"
else
	echo "Image is incorrect!!!"
fi
let "hvpad_size=$ckpad_size+1024"

dd if=$gap_bin bs=1 skip=$hvpad_size count=2 of=gap.hv > /dev/null 2>&1

hexhv=`hexdump gap.hv  | grep 0000000 | sed -e "s/0000000 //" | sed -e "s/ //g"`

checksum=""

i=0
len=${#hexhv}

while [ $i -lt $len ]
do
        temp=`expr $i \% 2`
	temp_4=`expr $i \% 4`
	if [ $temp_4 -lt 2 ];then
        	pre_ck=${pre_ck}${hexhv:$i:1}
	else
	        if [ $temp -eq 0 ]; then
        	        sufix_ck=${hexhv:$i:1}
        	else
                	sufix_ck=${sufix_ck}${hexhv:$i:1}
        		if [ $mips_flag -eq 0 ];then
				checksum=${checksum}${sufix_ck}${pre_ck}
			else
				checksum=${checksum}${pre_ck}${sufix_ck}
				
			fi
			pre_ck=""
			sufix_ck=""
        	fi
		
	fi
	let i++
done


echo "Head version: "$checksum


rm -f  gap.pad gap.hv gap.ck gap.img xaa xab


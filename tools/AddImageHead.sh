gap_img=$1

image_path=$2

if [ $# -eq 0 ];then
	echo "Please enter the parameter"
	exit
fi

echo $image_path
if [ -e  ${image_path}/${gap_img} ];then
	gap_version=`echo ${gap_img} | sed -e "s/\.img//"`
fi
echo $gap_version

if [ -z "${gap_version}" ]; then
	echo "gap version error"
	echo $gap_version
	exit
fi


echo "{\"version\":\"${gap_version}\", \"algorithm\":\"MD5\"}" > ${image_path}/gap.head
cat ${image_path}/gap.head
vhead_size=`du -b ${image_path}/gap.head`

vhead_size=`echo $vhead_size | sed -e "s/ [\.]*\/.*\/gap\.head$//"`

echo $vhead_size

let "vpad_size=4096-$vhead_size"

echo $vpad_size

dd if=/dev/zero bs=1 count=$vpad_size of=${image_path}/gap.pad

cat ${image_path}/gap.head ${image_path}/gap.pad > ${image_path}/gap.head.img

seg1=${image_path}/${gap_version}.seg1

cat ${image_path}/${gap_img} ${image_path}/gap.head.img > ${seg1}

cksum_t=`md5sum ${seg1}`

echo $cksum_t

cksum=`expr substr "${cksum_t}"  1 32`

echo $cksum


for((i=0;i<${#cksum}; i++))
do
        temp=`expr $i \% 2`
        if [ $temp -eq 0 ]; then
                str_ck=${str_ck}"\x"${cksum:$i:1}
        else
                str_ck=${str_ck}${cksum:$i:1}
        fi
done

echo -e $str_ck > ${image_path}/gap.checksum

#cat gap.checksum
#hexdump gap.checksum

ckhead_size=`du -b ${image_path}/gap.checksum`
echo $ckhead_size
ckhead_size=`echo ${ckhead_size} | sed -e "s/ [\.]*\/.*\/gap\.checksum$//"`
echo $ckhead_size

let "ckpad_size=1024-$ckhead_size"
echo $ckpad_size
dd if=/dev/zero bs=1 count=$ckpad_size of=${image_path}/gap.checksum.pad

cat ${image_path}/gap.checksum ${image_path}/gap.checksum.pad > ${image_path}/gap.checksum.img

seg2=${image_path}/${gap_version}.seg2

cat $seg1 ${image_path}/gap.checksum.img > $seg2

echo -e "\x47\xBC" > ${image_path}/gap.ver

dd if=${image_path}/gap.ver bs=1 count=2 of=${image_path}/gap.ver.img

bin_name=${image_path}/${gap_version}.bin

cat $seg2 ${image_path}/gap.ver.img > $bin_name

rm -f ${image_path}/*.seg1
rm -f ${image_path}/*.seg2
rm -f ${image_path}/gap.*





#TODO: clean.sh dir_w_bbs

dir_to_clean=$1

rm $dir_to_clean/*.ann.bbs
rm $dir_to_clean/*.unann.bbs
rm $dir_to_clean/*.dict
rm $dir_to_clean/*.verify.txt
rm $dir_to_clean/data/*
rm $dir_to_clean/label/*
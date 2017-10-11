#TODO: input: $dirprefix $bin1 $binann1 $bin2 $binann2 ... (if annotations are available)
#input: $dirprefix $bin1 $bin1 $bin2 $bin2 ... (if no annotations)
#$dirprefix has no trailing slash (it must be given "/features/" and "/labels/" in create_obf_csv.py)

printf "0" > create_obf_csv.py.next_csv

#get parallel arrays of bin/binann from entwined input
declare -a bins
declare -a binanns
dirprefix=""
bin_pred=1
bin_count=0
arg_count=0
#TODO: change "file" to "arg"
for file in "$@"                                                                 
do                               
		if [ $arg_count -eq 0 ]
		then
			dirprefix="$file"
			arg_count=$(($arg_count + 1))
			continue
	    fi
		
        if [ $bin_pred -eq 1 ]
		then
			bins[$bin_count]="$file"
		else
			binanns[$bin_count]="$file"
		fi
		
		if [ $bin_pred -eq 1 ]
		then
			bin_pred=0
		else
			bin_count=$(($bin_count + 1))
			bin_pred=1
		fi
	
	arg_count=$(($arg_count + 1))
done

#TODO: make sure dirprefix exists
if [ -d ../../data/Binary/intermediary_data/$dirprefix ]
then
	:
else
	mkdir ../../data/Binary/intermediary_data/$dirprefix
fi

if [ -d ../../data/Binary/neuralnet_data/$dirprefix ]
then
	:
else
	mkdir ../../data/Binary/neuralnet_data/$dirprefix
fi

echo "./generate_csvs.sh $@" > ../../data/Binary/intermediary_data/$dirprefix/invocation.txt
echo "./generate_csvs.sh $@" > ../../data/Binary/neuralnet_data/$dirprefix/invocation.txt

for ((i=0;i<${#bins[@]};++i));
do
	next_csv=$(cat create_obf_csv.py.next_csv)
	printf "${bins[$i]} starting at $next_csv\n"
	./create_csvs_from_bin.sh ${bins[$i]} ${binanns[$i]} $next_csv $dirprefix
	#printf "array: ${bins[$i]} ${binanns[$i]}\n"
done

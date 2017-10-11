#!/bin/bash
#TODO: move first echo to only if step is invoked

bin=$1
binann=$2
binName=$(basename $1)
binannName=$(basename $2)
num=$3
dirprefix=$4

if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binannName.unann.bbs ]
then
	echo "$binannName.unann.bbs already exists"
else
	echo "Creating basic block list out of $binannName"
	idaw64 -A -S"../munge/bbify.py ../../data/Binary/intermediary_data/$dirprefix/$binannName.unann.bbs" $binann
	if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binannName.unann.bbs ]
	then
		:
	else
		echo "Creating $binannName.unann.bbs failed"
		exit -1
	fi
fi

if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binName.unann.bbs ]
then
	echo "$binName.unann.bbs already exists"
else
	echo "Creating basic block list out of $binName"
	idaw64 -A -S"../munge/bbify.py ../../data/Binary/intermediary_data/$dirprefix/$binName.unann.bbs" $bin
	if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binName.unann.bbs ]
	then
		:
	else
		echo "Creating $binName.unann.bbs failed"
		exit -1
	fi
fi

if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binannName.ann.bbs ]
then
	echo "$binannName.ann.bbs already exists"
else
	echo "Annotating basic block list with $binannName"
	idaw64 -A -S"../munge/annotate_bbs.py ../../data/Binary/intermediary_data/$dirprefix/$binannName.unann.bbs ../../data/Binary/intermediary_data/$dirprefix/$binannName.ann.bbs" $binann
	if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binannName.ann.bbs ]
	then
		:
	else
		echo "Creating $binannName.ann.bbs failed"
		exit -1
	fi
fi

#if [ -s $bin.verify.txt ]
#then
#	echo "$bin.verify.txt already exists"
#else
#	echo "Printing possible discrepant basic blocks to $bin.verify.txt"
#	python verify_bb_order.py $binann.ann.bbs $bin.unann.bbs > $bin.verify.txt
#	if [ -s $bin.verify.txt ]
#	then
#		:
#	else
#		echo "Creating $bin.verify.txt failed"
#		exit -1
#	fi
#fi

if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binannName.dict ]
then
	echo "$binannName.dict already exists"
else
	echo "Making address to annotation dictionary"
	python ../munge/create_annotated_addrs.py ../../data/Binary/intermediary_data/$dirprefix/$binannName.ann.bbs ../../data/Binary/intermediary_data/$dirprefix/$binName.unann.bbs ../../data/Binary/intermediary_data/$dirprefix/$binannName.dict
	if [ -s ../../data/Binary/intermediary_data/$dirprefix/$binannName.dict ]
	then
		:
	else
		echo "Creating $binannName.dict failed"
		exit -1
	fi
fi

echo "Creating folders for features and labels"

if [ -d ../../data/Binary/neuralnet_data/$dirprefix/features ]
then
	:
else
	mkdir ../../data/Binary/neuralnet_data/$dirprefix/features
fi

if [ -d ../../data/Binary/neuralnet_data/$dirprefix/labels ]
then
	:
else
	mkdir ../../data/Binary/neuralnet_data/$dirprefix/labels
fi

echo "Creating csvs out of $binName"
python ../munge/create_obf_csv.py $bin ../../data/Binary/intermediary_data/$dirprefix/$binannName.dict ../../data/Binary/neuralnet_data/$dirprefix $num

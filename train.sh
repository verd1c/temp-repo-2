#!/bin/zsh

LAYERS = 10

# 3 variables here
# - rounds = 0
# - layers = 10
# - batches = 3

for (( l = 0; l < 10; ++l ));
do

	# do per layer training
	darknetp classifier train -pp_start 7 -pp_end 9 cfg/mnist.dataset cfg/mnist_lenet.cfg

	sleep 2s
	
	sshpass -p 123 scp -o StrictHostKeyChecking=no tmp/backup/mnist_lenet.weights user@10.0.2.2:~/Desktop/weights/weights${l}

done

echo "Finished training ${LAYERS} rounds"

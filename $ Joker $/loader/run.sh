#!/bin/sh

killpid() {
        pkill -9 loader
        sleep 100
}

killpid &

while true; do
	rm -rf .tempload
        cat *.txt | uniq | shuf >.tempload
	cat .tempload | ./loader
done


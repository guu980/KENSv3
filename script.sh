#!/bin/bash

CNT=0
make &> /dev/null
while true; do
	build/testTCP --gtest_filter="TestEnv_Reliable.TestAccept_*:TestEnv_Any.TestAccept_*:TestEnv_Any.TestConnect_BeforeAccept:TestEnv_Any.TestConnect_AfterAccept:TestEnv_Any.TestClose_*" > result.txt

	if (( $? != 0 )); then
		break
	fi

	CNT=$((CNT+1))

	if (( $CNT % 10 == 0)); then
		echo "Tested $CNT times."
	fi

done

echo "Tested $CNT times."

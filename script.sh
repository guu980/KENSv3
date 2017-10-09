#!/bin/bash

CNT=1
make &> /dev/null
while true; do
	build/testTCP --gtest_filter="TestEnv_Reliable.TestAccept_*:TestEnv_Any.TestAccept_*:TestEnv_Any.TestConnect_BeforeAccept:TestEnv_Any.TestConnect_AfterAccept:TestEnv_Any.TestClose_*" > result.txt

	if (( $? != 0 )); then
		break
	fi

	if (( $CNT % 10 == 0)); then
		echo "Tested $CNT times."
	fi

	CNT=$((CNT+1))

done

echo "Tested $CNT times."

cat result.txt | mail -s "KENSv3 Test Failed ($CNT tries)" tonyshin@kaist.ac.kr
cat result.txt | mail -s "KENSv3 Test Failed ($CNT tries)" alex9801@kaist.ac.kr

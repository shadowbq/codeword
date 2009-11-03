<?php

//*************************************
//			CUSTOM VARIABLES
//*************************************
//change these as desired
//
//there are 16 columns as of 4/2009
$max_columns=16;
$csvname="LUT.csv";
$outfilename="LUT_C.txt";
//*************************************

// * DO NOT MODIFY BELOW THIS LINE !!!! *//

if (!is_file($csvname))
{
	echo "ERROR:  '$csvname' was not found.";
	exit;
}

//change this to reflect any new columns added to the LUT
//load the html file
$lines=file($csvname);

//we will output a file with C code for pasting into lut.c
$out=fopen($outfilename,"w+");
$count=0;

foreach ($lines as $line_num => $line)
{
	$line_data=explode(",",$line);
	
	//if the column count has changed, this will require updates to
	//	-this script
	//	-it's parent, GetLookupTable.php
	//	-LUT.h and LUT.c in kgsp
	if (count($line_data) != $max_columns)
	{
		echo "\nERROR:  Column count is not 16.  Were more OS versions added to the table since this script was last updated??";
		echo "\nQuitting.";
		exit;
	}
	
	//the first entry on the line is the function name
	//format:  KnownGood_ServiceFunctionNames[0]="NtConnectPort";
	$str="KnownGood_ServiceFunctionNames[".$count."]=\"".$line_data[0]."\";\n";
	fwrite($out,$str);
	
	//loop through $max_columns-1 and populate the SSDT index for known OS builds
	//start at column=1 to skip the function name
	for($i=1;$i<=$max_columns-1;$i++)
	{
		//if the index is null, that means this version of the OS does not 
		//have this API function...so set it to -1
		if ($line_data[$i] == "")
			$index="-1";
		else
			$index=$line_data[$i];
			
		//format:  
		//	KnownGood_ServiceFunctionAddresses[0][0]=0x01DE;
		//	KnownGood_ServiceFunctionAddresses[0][1]=0x0022;
		//	......
		//  KnownGood_ServiceFunctionAddresses[num_lines][max_columns-1]=0x01FF;	
		$str="KnownGood_ServiceFunctionAddresses[".$count."][".strval($i-1)."]=".$index.";\n";
		fwrite($out,$str);
	}
	
	$count++;
}

fclose($out);

echo "Done!";
?>


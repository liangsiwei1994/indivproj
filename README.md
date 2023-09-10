# indivproj

## Before running any of the scripts, please set up the virtual environment using the requirements.txt file.

## The TTPClassifier folder contains the original code by Alam et al. [1].
https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb

## Running the tests
Run the script to extract the attack phrases and sentence <br>
`python <path to inference_originalFilter6_sentence_phrase_regex_YARA_temp.py> --entity-extraction-weight=<path to entity_ext.pt> --sentence-classification-weight=<path to sent_cls.pt> --input-doc=<path to test reports to be analysed> --save-path=<path to any .txt document to save printed extracted phrases/sentences>`

Then run the script to identify MITRE techniques <br>
`python <path to part2original_atkBert_append162b2c2_46_regexv11.py> --sentence_file=<path to the .txt file of --save_path when running the script to extract phrases and sentences> > <Any .txt file to print the results>`

Replace the 

## Running the python app
Use Spyder of Anaconda to be sure it worked similarly. Simply run the `PythonApp.py` under the "Python App" folder.

## Credits
Md Tanvirul Alam, Dipkamal Bhusal, Youngja Park, and Nidhi Rastogi. Looking beyond iocs: Automatically extracting attack patterns from external cti. arXiv preprint arXiv:2211.01753, 2022. pages


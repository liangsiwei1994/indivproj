# Liang Si Wei MSc Computing 2022-2023 Individual Project GitHub Repository

## Before running any of the scripts, please set up the virtual environment using the requirements.txt file.

## The TTPClassifier folder contains the original code by Alam et al. [1].
https://github.com/aiforsec/LADDER/blob/main/notebooks/attack-pattern-extraction.ipynb

## Running the tests
First, create a folder named "models", and download the models by Alam et al. [1] to use from: 
1. https://drive.google.com/uc?id=1yYRNoV4SFwcS1HAgrwxNQftqQVnaXLGo (for entity_ext.pt)
2. https://drive.google.com/uc?id=15YJgo4iqfQ7zWoHLBOnHOW4BV3hsGENY (for sent_cls.pt)

Secondly, place the model at the same level directory of the python scripts to be run, or within the python app folder itself if you are running the python app.

Thirdly, run the script to extract the attack phrases and sentence <br>
`python <path to inference_originalFilter6_sentence_phrase_regex_YARA_temp.py> --entity-extraction-weight=<path to entity_ext.pt> --sentence-classification-weight=<path to sent_cls.pt> --input-doc=<path to test reports to be analysed> --save-path=<path to any .txt document to save printed extracted phrases/sentences>`

Lastly, run the script to identify MITRE techniques <br>
`python <path to part2original_atkBert_append162b2c2_46_regex.py> --sentence_file=<path to the .txt file of --save_path when running the script to extract phrases and sentences> > <Any .txt file to print the results>`

*Replace the `inference_originalFilter6_sentence_phrase_regex_YARA_temp.py` with `inference_original.py`, and `part2original_atkBert_append162b2c2_46_regex.py` with `part2original.py` to run the original TTPClassifier.
*As the final experiment contains similar functions to the python app, please look at the python app python files to see which code was added, adapted, or taken from Alam et al. [1]

## Running the python app
Use Spyder of Anaconda to be sure it worked similarly. Simply run the `PythonApp.py` under the "Python App" folder, after downloading the models in step 1 and 2 above.

## Credits
[1] Md Tanvirul Alam, Dipkamal Bhusal, Youngja Park, and Nidhi Rastogi. Looking beyond iocs: Automatically extracting attack patterns from external cti. arXiv preprint arXiv:2211.01753, 2022. pages

## Contact
Please reach out to sl222@ic.ac.uk if more information about the code is needed. For the other experiments, to prevent the GitHub from becoming too messy, please feel free to contact me for the files. Thank you!

